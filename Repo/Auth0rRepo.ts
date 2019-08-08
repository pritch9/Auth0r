import Knex, {TableBuilder} from 'knex';
import {ENV, error, getEnv, log, warn} from "../src/Utilities/Utilities";
import bcrypt from 'bcrypt';
import {Auth0r} from "../src";
import email_validator from "email-validator";
import deasync from 'deasync';

let dev = getEnv() === ENV.DEVELOPMENT;
let knex: Knex = undefined; // protected static variable

let table_schemas = {
	Users: (user_identifier: string) => (table: TableBuilder) => {
		table.increments('id');
		table.string(user_identifier);
		table.binary('password', 60);
		table.string('o', 32);
	},
	Auth0r_Log: () => (table: TableBuilder) => {
		table.increments('id');
		table.string('identifier');
		table.string('prod_error');
		table.string('dev_error');
		table.string('message');
	}
};

class Auth0rRepoOptions {
	connection: any;
	user_identifier: string;
}

export class Auth0rRepo {
	private readonly user_identifier: string;
	private logger: Auth0rLogger;
	protected _ready = false;
	// public set ready(ready: boolean) { }
	public get ready() { return this._ready; }
	private errors = {
		INVALID_CREDS: undefined,
		DATABASE_ERROR: new Error('Oops, double check that the database is up and running. \
									If not, get it up and retry. \
									Otherwise, there may be an issue with your configuration.'),
		INVALID_OPAQUE: new Error('Something went wrong!  Please try to log in again'),
		REG_USER_EXISTS: undefined,
		SERVER_ERROR: new Error('Something went wrong!  Please try again in a little bit.'),
		INVALID_EMAIL: new Error('Please enter a valid email address.'),
		BAD_PASSWORD: new Error('Password requirements: \
								\t- At least 8 characters long \
								\t- contains at least 1 lowercase character \
								\t- contains at least 1 uppercase character \
								\t- contains at least one special character (!@#$%^&*-+?)'),
		UNAUTHORIZED_ACCESS: new Error('Uh Oh!  Looks like something fishy is going on.  We are logging you out for your account safety.  For more info, please contact support and we would be happy to explain :)')

	};
	private static passwordRequirement = new RegExp(/(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[0-9].*)(?=.*[!@#$%^&*-+?].*).{8,}/);

	constructor(options: Auth0rRepoOptions) {
		knex = Knex(options.connection);
		this.user_identifier = options.user_identifier;
		this.logger = new Auth0rLogger({
			user_identifier: this.user_identifier
		});
		this.initErrors();
		warn('Waiting for database confirmation... this may take a while');
		let initDatabaseSync = deasync(Auth0rRepo.initDatabase);

		try {
			initDatabaseSync(this);
			this._ready = true;
		} catch (err) {
			error('Initialization of database failed!  Check logs for more info');
		}
	}

	private initErrors() {
		this.errors.INVALID_CREDS = new Error(`Invalid ${this.user_identifier} or password!`);
		this.errors.INVALID_CREDS.name = 'INVALID_CREDENTIALS';
		this.errors.DATABASE_ERROR.name = 'DATABASE_ERROR';
		this.errors.INVALID_OPAQUE.name = 'INVALID_OPAQUE';
		this.errors.REG_USER_EXISTS = new Error(`An account with this ${this.user_identifier} already exists!`);
		this.errors.REG_USER_EXISTS.name = 'REG_USER_EXISTS';
		this.errors.INVALID_EMAIL.name = 'INVALID_EMAIL';
		this.errors.BAD_PASSWORD.name = 'BAD_PASSWORD';
	}

	login(user_id: string, password: string): Promise<string> {
		return new Promise<string>((resolve, reject) => {
			let handleError = (prodError: Error, devError?: Error) => this.handleError(reject, user_id, 'login', prodError, devError);

			knex.select('password')
				.from('Users')
				.where(this.user_identifier, user_id).then((results) => {
					if (results.length) {
						let hash = results[0].password;

						bcrypt.compare(password, hash).then((res) =>{
							if (res) {
								// passwords match!
								let token = Auth0r.generateOpaqueKey();
								knex.table('Users')
									.update({o: token})
									.where(this.user_identifier, user_id).then(() => {
										// Success
										resolve(token);
								}).catch(err => handleError(this.errors.DATABASE_ERROR, err));
							} else {
								handleError(this.errors.INVALID_CREDS);
							}
						});
					} else {
						handleError(this.errors.INVALID_CREDS);
					}
				}).catch(err => handleError(this.errors.DATABASE_ERROR, err));
		});
		// On Success, return opaque
		// On Fail, return undefined
	}
	verifyOpaque(user_id: string, token: string, request): Promise<boolean> {
		return new Promise<boolean>((resolve, reject) => {
			let handleError = (prodError: Error, devError?: Error) => this.handleError(reject, user_id, 'verifyOpaque', prodError, (devError) ? devError : prodError);

			knex.table('Users')
				.select('o')
				.where(this.user_identifier, user_id)
				.then((result) => {
					if (result.length) {
						if(result[0].o === token) {
							// authorized user
							request.body.o = Auth0r.generateOpaqueKey();
							knex.table('Users')
								.update({o: request.body.o}).then(() => {
									resolve(true);
								}).catch((err) => handleError(this.errors.SERVER_ERROR, err));
						} else {
							let devError = new Error(JSON.stringify(request.headers));
							devError.name = "UNAUTHORIZED_ACCESS";
							handleError(this.errors.UNAUTHORIZED_ACCESS, devError);
							knex.table('Users')
								.update({o: null})
								.then(() => { /* do nothing */ })
								.catch((err) => this.logger.logError(user_id, 'verifyOpaque - set opaque', err, err))
						}
					} else {
						handleError(this.errors.INVALID_OPAQUE);
					}
				}).catch(err => handleError(err));
		});
	}
	register(user_id: string, password: string): Promise<string> {
		return new Promise<string>((resolve, reject) => {
			let handleError = (prodError: Error, devError?: Error) => this.handleError(reject, user_id, 'register', prodError, devError ? devError : prodError);

			if (this.user_identifier === 'email' && !email_validator.validate(user_id)) {
				handleError(this.errors.INVALID_EMAIL);
				return;
			}

			if (!Auth0rRepo.passwordRequirement.test(password)) {
				handleError(this.errors.BAD_PASSWORD);
				return;
			}
			bcrypt.genSalt(12, (err, salt) => {
				if (err) {
					return handleError(this.errors.SERVER_ERROR, err);
				}
				bcrypt.hash(password, salt, (err, hash) => {
					if (err) {
						handleError(this.errors.SERVER_ERROR, err);
					}
					// Now we can store data
					let userData = {
						password: hash
					};
					userData[this.user_identifier] = user_id;
					knex.table('Users')
						.insert(userData)
						.then(() => {
							// Success
							resolve(user_id);
						}).catch((err) => {
							if(err.code === 0) {
								handleError(this.errors.REG_USER_EXISTS, err);
							} else {
								handleError(this.errors.SERVER_ERROR, err);
							}
						});
				});
			});
		});
	}

	private handleError(reject, user_id: string, func: string, prodError: Error, devError?: Error) {
		reject((dev) ? devError : prodError);
		setTimeout(() => this.logger.logError(user_id, func, prodError, devError ? devError : prodError));
	}

	private static async initDatabase(repo: Auth0rRepo, cb: (err, result) => void) {
		warn('Initializing database...');
		try {
			await knex.raw('SELECT 1+1 AS result');
			log('Connection successful.');
		} catch (err) {
			repo.logger.logError('DATABASE_CONNECTION', 'initDatabase', err, err);
			cb(new Error('Unable to connect to database!  Please double check your connection settings.'), null);
		}
		log();
		log('Checking table existence ...');
		for (let table of Object.keys(table_schemas)) {
			log();
			log(`Does \`${table}\` exist?`);
			let exists = false;
			try {
				exists = await knex.schema.hasTable(table);
			} catch (err) {
				repo.logger.logError(table, 'initDatabase', err, err);
				cb(new Error(`Unable to check table \`${table}\`!  Check console to see error message.`), null);
			}
			if (!exists) {
				// Table does not exist
				log('no ... creating table');
				try {
					await knex.schema.createTable(table, table_schemas[table](repo.user_identifier));
					log(`Table \`${table}\` created!`);
				} catch (err) {
					repo.logger.logError(table, 'initDatabase', err, err);
					cb(new Error(`Unable to create table \`${table}\`!  Check console to see error message.`), null);
				}
			} else {
				log('yes ... continuing');
			}
		}
		log();
		log('done.');
		log();
		cb(null, true);
	}
}
class Auth0rLoggerOptions {
	user_identifier: string;
}
class Auth0rLogger {
	private user_identifier: string;

	constructor(options: Auth0rLoggerOptions) {
		this.user_identifier = options.user_identifier;
	}

	logError(identifier: string, func: string, prodError: Error, devError: Error) {
		if (dev) {
			error(`============ Error ============\n
                            \tIdentifier:\t${identifier}\n
                            \tFunction:\t${func}\n
                            \tProd Error:\t${prodError.name}\n
                            \tDev Error:\t${devError.name}\n
                            \tMessage:\t${devError.message}\n
                            ===============================`)
		} else {
			knex.table('Auth0r_Log')
				.insert({identifier, func, prod_error: prodError.name, dev_error: devError.name, message: devError.message }).catch((err) => {
				error(err);
			});
		}
	}
}
