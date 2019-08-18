"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const bcrypt_1 = __importDefault(require("bcrypt"));
const deasync_1 = __importDefault(require("deasync"));
const email_validator_1 = __importDefault(require("email-validator"));
const knex_1 = __importDefault(require("knex"));
const index_1 = require("../index");
const Auth0rLogger_1 = require("../Logger/Auth0rLogger");
const Utilities_1 = require("../Utilities/Utilities");
const dev = Utilities_1.getEnv() === Utilities_1.ENV.DEVELOPMENT;
let knex; // protected static variable
const hashSync = deasync_1.default(bcrypt_1.default.hash);
const genSaltSync = deasync_1.default(bcrypt_1.default.genSalt);
const compareSync = deasync_1.default(bcrypt_1.default.compare);
const table_schemas = {
    Auth0r_Log: () => (table) => {
        table.increments('id');
        table.string('identifier');
        table.string('prod_error');
        table.string('dev_error');
        table.string('message');
        table.dateTime('date');
    },
    Auth0r_Log_Flags: () => (table) => {
        table.string('identifier');
        table.string('identifier_value');
        table.string('flag');
        table.string('flag_value');
    },
    Users: (user_identifier) => (table) => {
        table.increments('id');
        table.string(user_identifier);
        table.binary('password', 60);
        table.string('o', 32);
    },
};
class Auth0rRepo {
    constructor(options) {
        // tslint:disable-next-line:variable-name
        this._ready = false;
        this.errors = {
            BAD_PASSWORD: new Error('Password requirements: \
								\t- At least 8 characters long \
								\t- contains at least 1 lowercase character \
								\t- contains at least 1 uppercase character \
								\t- contains at least one special character (!@#$%^&*-+?)'),
            DATABASE_ERROR: new Error('Oops, double check that the database is up and running. \
									If not, get it up and retry. \
									Otherwise, there may be an issue with your configuration.'),
            INVALID_CREDS: undefined,
            INVALID_EMAIL: new Error('Please enter a valid email address.'),
            INVALID_OPAQUE: new Error('Something went wrong!  Please try to log in again'),
            REG_USER_EXISTS: undefined,
            SERVER_ERROR: new Error('Something went wrong!  Please try again in a little bit.'),
            UNAUTHORIZED_ACCESS: new Error('Uh Oh!  Looks like something fishy is going on. \
										We are logging you out for your account safety. \
										For more info, please contact support and we would be happy to explain :)'),
        };
        knex = knex_1.default(options.connection);
        this.user_identifier = options.user_identifier;
        this.logger = new Auth0rLogger_1.Auth0rLogger({
            knex,
            user_identifier: this.user_identifier,
        });
        this.initErrors();
        Utilities_1.warn('Waiting for database confirmation... this may take a while');
        const initDatabaseSync = deasync_1.default(Auth0rRepo.initDatabase);
        try {
            initDatabaseSync(this);
            this._ready = true;
        }
        catch (err) {
            Utilities_1.error('Initialization of database failed!  Check logs for more info');
        }
    }
    // public set ready(ready: boolean) { }
    get ready() {
        return this._ready;
    }
    static initDatabase(repo, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            Utilities_1.warn('Initializing database...');
            try {
                yield knex.raw('SELECT 1+1 AS result');
            }
            catch (err) {
                repo.logger.logError('DATABASE_CONNECTION', 'initDatabase', err, err);
                cb(new Error('Unable to connect to database!  Please double check your connection settings.'), null);
            }
            for (const table of Object.keys(table_schemas)) {
                let exists = false;
                try {
                    exists = yield knex.schema.hasTable(table);
                }
                catch (err) {
                    repo.logger.logError(table, 'initDatabase', err, err);
                    cb(new Error(`Unable to check table \`${table}\`!  Check console to see error message.`), null);
                }
                if (!exists) {
                    // Table does not exist
                    try {
                        yield knex.schema.createTable(table, table_schemas[table](repo.user_identifier));
                    }
                    catch (err) {
                        repo.logger.logError(table, 'initDatabase', err, err);
                        cb(new Error(`Unable to create table \`${table}\`!  Check console to see error message.`), null);
                    }
                }
            }
            cb(null, true);
        });
    }
    login(user_id, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const handleError = (prodError, devError) => this.handleError(user_id, 'login', prodError, devError);
            let results;
            try {
                results = yield knex.select('id', 'password')
                    .from('Users')
                    .where(this.user_identifier, user_id);
            }
            catch (err) {
                handleError(this.errors.DATABASE_ERROR, err);
            }
            if (results.length) {
                const hash = results[0].password;
                const id = results[0].id;
                const match = compareSync(password, hash);
                if (match) {
                    // passwords match!
                    const token = index_1.Auth0r.generateOpaqueKey();
                    try {
                        yield knex.table('Users')
                            .update({ o: token })
                            .where('id', id);
                        // Success
                        return { id, opaque: token };
                    }
                    catch (err) {
                        handleError(this.errors.DATABASE_ERROR, err);
                    }
                }
                else {
                    handleError(this.errors.INVALID_CREDS);
                }
            }
            else {
                handleError(this.errors.INVALID_CREDS);
            }
            // On Success, return opaque
            // On Fail, return undefined
        });
    }
    verifyOpaque(user_id, token, request) {
        return __awaiter(this, void 0, void 0, function* () {
            const handleError = (prodError, devError) => this.handleError(String(user_id), 'verifyOpaque', prodError, (devError) ? devError : prodError);
            const results = yield knex.table('Users')
                .select('o')
                .where('id', user_id);
            if (results.length) {
                if (results[0].o === token) {
                    // authorized user
                    if (!request.body) {
                        request.body = {};
                    }
                    request.body.o = index_1.Auth0r.generateOpaqueKey();
                    try {
                        yield knex.table('Users')
                            .update({ o: request.body.o })
                            .where('id', user_id);
                        return true;
                    }
                    catch (err) {
                        handleError(this.errors.SERVER_ERROR, err);
                    }
                }
                else {
                    const devError = new Error(JSON.stringify(request.headers));
                    devError.name = 'UNAUTHORIZED_ACCESS';
                    handleError(this.errors.UNAUTHORIZED_ACCESS, devError);
                    try {
                        yield knex.table('Users')
                            .update({ o: null })
                            .where('id', user_id);
                    }
                    catch (err) {
                        this.logger.logError(String(user_id), 'verifyOpaque - set opaque', err, err);
                    }
                }
            }
            else {
                handleError(this.errors.INVALID_OPAQUE);
            }
        });
    }
    register(user_id, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const handleError = (prodError, devError) => this.handleError(user_id, 'register', prodError, devError ? devError : prodError);
            if (this.user_identifier === 'email' && !email_validator_1.default.validate(user_id)) {
                handleError(this.errors.INVALID_EMAIL);
                return;
            }
            if (!Auth0rRepo.passwordRequirement.test(password)) {
                handleError(this.errors.BAD_PASSWORD);
                return;
            }
            let salt;
            let hash;
            try {
                salt = genSaltSync(12);
                hash = hashSync(password, salt);
            }
            catch (err) {
                handleError(this.errors.SERVER_ERROR, err);
            }
            // Now we can store data
            const userData = {
                password: hash,
            };
            userData[this.user_identifier] = user_id;
            try {
                yield knex.table('Users')
                    .insert(userData);
                return user_id;
            }
            catch (err) {
                if (err.code === 0) {
                    handleError(this.errors.REG_USER_EXISTS, err);
                }
                else {
                    handleError(this.errors.SERVER_ERROR, err);
                }
            }
        });
    }
    initErrors() {
        this.errors.INVALID_CREDS = new Error(`Invalid ${this.user_identifier} or password!`);
        this.errors.INVALID_CREDS.name = 'INVALID_CREDENTIALS';
        this.errors.DATABASE_ERROR.name = 'DATABASE_ERROR';
        this.errors.INVALID_OPAQUE.name = 'INVALID_OPAQUE';
        this.errors.REG_USER_EXISTS = new Error(`An account with this ${this.user_identifier} already exists!`);
        this.errors.REG_USER_EXISTS.name = 'REG_USER_EXISTS';
        this.errors.INVALID_EMAIL.name = 'INVALID_EMAIL';
        this.errors.BAD_PASSWORD.name = 'BAD_PASSWORD';
    }
    handleError(user_id, func, prodError, devError) {
        setTimeout(() => this.logger.logError(user_id, func, prodError, devError ? devError : prodError));
        throw (dev) ? devError : prodError;
    }
}
Auth0rRepo.passwordRequirement = new RegExp(/(?=.*[a-z].*)(?=.*[A-Z].*)(?=.*[0-9].*)(?=.*[!@#$%^&*-+?].*).{8,}/);
exports.Auth0rRepo = Auth0rRepo;
//# sourceMappingURL=Auth0rRepo.js.map