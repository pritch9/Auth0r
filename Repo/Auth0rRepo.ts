import Knex from 'knex';
import {ENV, error, getEnv, log, warn} from "../src/Utilities/Utilities";
import bcrypt from 'bcrypt';
import {Auth0r} from "../src";
import email_validator from "email-validator";

let dev = getEnv() === ENV.DEVELOPMENT;
let knex: Knex = undefined; // protected static variable

class Auth0rRepoOptions {
	connection: any;
	user_identifier: string;
}

export class Auth0rRepo {
	protected static knex: any;
	private readonly user_identifier: string;
	private logger: Auth0rLogger;
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
	private static passwordRequirement = new RegExp(/(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[!@#$%^&*-+?].*)(?=[.*]{8,})/);

	constructor(options: Auth0rRepoOptions) {
		knex = Knex(options.connection);
		this.user_identifier = options.user_identifier;
		this.logger = new Auth0rLogger({
			user_identifier: this.user_identifier
		});
		this.initErrors();
		this.initDatabase();
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
				.select('opaque')
				.where(this.user_identifier, user_id)
				.then((result) => {
					if (result.length) {
						if(result[0] === token) {
							// authorized user
							request.body.o = Auth0r.generateOpaqueKey();
							knex.table('Users')
								.update('opaque', token).then(() => {
									resolve(true);
								}).catch((err) => handleError(this.errors.SERVER_ERROR, err));
						} else {
							let devError = new Error(JSON.stringify(request.headers));
							devError.name = "UNAUTHORIZED_ACCESS";
							handleError(this.errors.UNAUTHORIZED_ACCESS, devError);
							knex.table('Users')
								.update('opaque', undefined)
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

			if (!email_validator.validate(user_id)) {
				handleError(this.errors.INVALID_EMAIL);
				return;
			}

			if (!password.match(Auth0rRepo.passwordRequirement)) {
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

	private initDatabase() {
		// Tables needed:
		//		Users
		//			id
		//			user_identifier
		//			password
		//			o
		//
		//		Auth0r_Log
		//			user_id
		//			func
		//			prod_error
		//			dev_error
		//			message
		log('------- [Auth0r] Loading Database -------');
		log('[Table: Users] checking table existence...');
		knex.schema.hasTable('Users').then((exists) => {
			if (!exists) {
				warn('[Table: Users] table does not exist - creating...');
				knex.schema.createTable('Users', (table) => {
					table.increments('id');
					table.string(this.user_identifier);
					table.binary('password', 60);
					table.string('o', 32);
				}).then(() => {
					// success
					log('[Table: Users] `Users` table created!');
				}).catch((err) => {
					// failure (probably table exists)
					error(err);
				});
			} else {
				log('[Table: Users] Table exists, continuing');
			}
		});

		log('[Table: Auth0r_Log] checking table existence...');
		knex.schema.hasTable('Auth0r_Log').then((exists) => {
			if (!exists) {
				warn('[Table: Auth0r_Log] table does not exist - creating...');
				knex.schema.createTable('Auth0r_Log', (table) => {
					table.increments('id');
					table.string('user_id');
					table.string('prod_error');
					table.string('dev_error');
					table.string('message');
				}).then(() => {
					// Success
					log('[Table: Auth0r_Log] `Auth0r_Log` table created!');
				}).catch(err => {
					error(err);
				});
			} else {
				log('[Table: Auth0r_Log] Table exists, continuing');
			}
		});
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

	logError(user_id: string, func: string, prodError: Error, devError: Error) {
		if (dev) {
			error(`============ Error ============\n
                            \tUser:\t${user_id}\n
                            \tFunction:\t${func}\n
                            \tProd Error:\t${prodError.name}\n
                            \tDev Error:\t${devError.name}\n
                            \tMessage:\t${devError.message}\n
                            ===============================`)
		} else {
			knex.table('Auth0r_Log')
				.insert({user_id, func, prod_error: prodError.name, dev_error: devError.name, message: devError.message }).catch((err) => {
				error(err);
			});
		}
	}
}
