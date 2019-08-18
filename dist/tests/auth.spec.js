"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("assert");
const bcrypt_1 = __importStar(require("bcrypt"));
const chai_1 = require("chai");
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const jwt = __importStar(require("jsonwebtoken"));
const knex_1 = __importDefault(require("knex"));
const path_1 = __importDefault(require("path"));
const src_1 = require("../src");
const Utilities_1 = require("../src/Utilities/Utilities");
const MiddlewareNext_1 = require("./Models/MiddlewareNext");
const MiddlewareResponse_1 = require("./Models/MiddlewareResponse");
const dir = __dirname;
const test_db = path_1.default.resolve(dir, './test.db');
const test_db_empty = path_1.default.resolve(dir, './test_empty.db');
const key_folder = path_1.default.resolve(__dirname, '../rsa_keys');
describe('Auth0r StartUp Suite', function () {
    const connection = test_db;
    before(function () {
        return __awaiter(this, void 0, void 0, function* () {
            deleteRSAKeys();
            chai_1.expect(fs_1.default.existsSync(key_folder)).to.be.false;
        });
    });
    beforeEach(function () {
        // delete old database
        process.env.NODE_ENV = 'development';
        newTestDatabase();
    });
    it('should generate RSA tokens if none exist', function () {
        const equal_instances = [
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                user_identifier: 'username',
            }),
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                public_key: 'df',
                user_identifier: 'username',
            }),
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: 'sdfg',
                user_identifier: 'username',
            }),
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: 'fasf',
                public_key: 'asdf',
                user_identifier: 'username',
            }),
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: '',
                public_key: '',
                user_identifier: 'username',
            }),
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: path_1.default.resolve(dir, './test_rsa_invalid/privkey.pem'),
                public_key: path_1.default.resolve(dir, './test_rsa_invalid/privkey.pem'),
                user_identifier: 'email',
            }),
            new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: path_1.default.resolve(dir, './test_rsa_empty/privkey.pem'),
                public_key: path_1.default.resolve(dir, './test_rsa_empty/privkey.pem'),
                user_identifier: 'email',
            }),
        ];
        let compareFn;
        for (const x of equal_instances) {
            if (compareFn !== undefined) {
                chai_1.expect(compareFn(x)).to.be.true;
            }
            compareFn = (y) => src_1.Auth0r.compareKeyTwins(x, y);
        }
        chai_1.expect(fs_1.default.existsSync(key_folder)).to.be.true;
        const keys = {
            private_key: path_1.default.resolve(__dirname, '../rsa_keys/privkey.pem'),
            public_key: path_1.default.resolve(__dirname, '../rsa_keys/pubkey.pem'),
        };
        chai_1.expect(fs_1.default.existsSync(keys.public_key)).to.be.true;
        chai_1.expect(fs_1.default.existsSync(keys.private_key)).to.be.true;
        for (const key of Object.keys(keys)) {
            const contents = fs_1.default.readFileSync(keys[key], { encoding: 'utf-8' });
            chai_1.expect(crypto_1.default[key === 'private_key' ? 'createPrivateKey' : 'createPublicKey'](contents)).to.not.throw;
        }
    });
    it('should use provided RSA token files', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const pub_key = path_1.default.resolve(__dirname, './test_rsa_valid/pubkey.pem');
            const priv_key = path_1.default.resolve(__dirname, './test_rsa_valid/privkey.pem');
            const auth0r = new src_1.Auth0r({
                connection,
                issuer: '',
                private_key: priv_key,
                public_key: pub_key,
                user_identifier: 'username',
            });
            const pub_contents = fs_1.default.readFileSync(pub_key, { encoding: 'UTF-8' });
            const priv_contents = fs_1.default.readFileSync(pub_key, { encoding: 'UTF-8' });
            chai_1.expect(src_1.Auth0r.compareKeys(auth0r, pub_contents, priv_contents));
        });
    });
    it('should use provided rsa key strings', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const pub_key = path_1.default.resolve(__dirname, './test_rsa_valid/pubkey.pem');
            const priv_key = path_1.default.resolve(__dirname, './test_rsa_valid/privkey.pem');
            const pub_contents = fs_1.default.readFileSync(pub_key, { encoding: 'UTF-8' });
            const priv_contents = fs_1.default.readFileSync(priv_key, { encoding: 'UTF-8' });
            const auth0r = new src_1.Auth0r({
                connection,
                issuer: '',
                private_key: priv_contents,
                public_key: pub_contents,
                user_identifier: 'username',
            });
            chai_1.expect(src_1.Auth0r.compareKeys(auth0r, pub_contents, priv_contents));
        });
    });
    it('should generate a random opaque key', function () {
        const hashMap = {};
        console.log('Example opaque key: %s', src_1.Auth0r.generateOpaqueKey());
        for (let x = 0; x < 10000; ++x) {
            const randomKey = src_1.Auth0r.generateOpaqueKey();
            if (randomKey.length !== 32) {
                assert_1.fail(`Random opaque key length invalid!  (length: ${randomKey.length})`);
            }
            if (hashMap[randomKey]) {
                assert_1.fail('Random Opaque key collision detected!');
            }
            hashMap[randomKey] = true;
        }
        chai_1.expect(Object.keys(hashMap)).to.have.length(10000);
    });
    it('should initialize database and function well', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const auth0r = new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: '',
                public_key: '',
                user_identifier: 'username',
            });
            chai_1.expect(auth0r.dbReady).to.be.true;
            const knex = knex_1.default(connection);
            const schema = {
                Auth0r_Log: {
                    columns: [
                        {
                            name: 'id',
                            primary_key: true,
                            test_value: '',
                            type: 'number',
                        },
                        {
                            name: 'identifier',
                            primary_key: false,
                            test_value: 'IDENTIFIER',
                            type: 'string',
                        },
                        {
                            name: 'prod_error',
                            primary_key: false,
                            test_value: 'PROD_ERROR',
                            type: 'string',
                        },
                        {
                            name: 'dev_error',
                            primary_key: false,
                            test_value: 'DEV_ERROR',
                            type: 'string',
                        },
                        {
                            name: 'message',
                            primary_key: false,
                            test_value: 'MESSAGE - MESSAGE',
                            type: 'string',
                        },
                        {
                            name: 'date',
                            primary_key: false,
                            test_value: new Date(),
                            type: 'Date',
                        },
                    ],
                },
                Auth0r_Log_Flags: {
                    columns: [
                        {
                            name: 'identifier',
                            primary_key: false,
                            test_value: 'identifier',
                            type: 'string',
                        },
                        {
                            name: 'identifier_value',
                            primary_key: false,
                            test_value: 'identifier_value',
                            type: 'string',
                        },
                        {
                            name: 'flag',
                            primary_key: false,
                            test_value: 'flag',
                            type: 'string',
                        },
                        {
                            name: 'flag_value',
                            primary_key: false,
                            test_value: 'flag_value',
                            type: 'string',
                        },
                    ],
                },
                Users: {
                    columns: [
                        {
                            name: 'id',
                            primary_key: true,
                            test_value: '',
                            type: 'number',
                        },
                        {
                            name: 'username',
                            primary_key: false,
                            test_value: 'username',
                            type: 'string',
                        },
                        {
                            name: 'password',
                            primary_key: false,
                            test_value: bcrypt_1.default.hashSync('Password1*', 12),
                            type: 'string',
                        },
                        {
                            name: 'o',
                            primary_key: false,
                            test_value: '9smMseYnhRy7t5spnUtsb7ACX3SREIKg',
                            type: 'string',
                        },
                    ],
                },
            };
            for (const tableName of Object.keys(schema)) {
                chai_1.expect(yield knex.schema.hasTable(tableName)).to.be.true;
                const columns = schema[tableName].columns;
                const insertValues = {};
                for (const column of columns) {
                    chai_1.expect(yield knex.schema.hasColumn(tableName, column.name)).to.be.true;
                    if (!column.primary_key) {
                        insertValues[column.name] = column.test_value;
                    }
                }
                try {
                    const insertResult = yield knex.table(tableName).insert(insertValues);
                    chai_1.expect(insertResult.length).to.equal(1);
                    chai_1.expect(insertResult[0]).to.equal(1);
                }
                catch (err) {
                    Utilities_1.error(err);
                    assert_1.fail(`Failed to insert test values into table! [Table: ${tableName}]`);
                }
                const results = yield knex.table(tableName).select('*');
                chai_1.expect(results.length).to.equal(1);
                chai_1.expect(Object.keys(results[0]).length).to.equal(columns.length);
                for (const column of columns) {
                    switch (column.type) {
                        case 'date':
                            if (column.type === 'Date') {
                                const dbDate = new Date(results[0][column.name]);
                                chai_1.expect(dbDate.getTime()).to.be.equal(column.test_value.getTime());
                            }
                            break;
                        case 'string':
                            chai_1.expect(results[0][column.name]).is.a('string');
                            break;
                        default:
                            continue;
                    }
                    if (!column.primary_key) {
                        chai_1.expect(results[0][column.name]).to.equal(column.test_value);
                    }
                }
            }
        });
    });
    it('should create a new user when registering', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const auth0r = new src_1.Auth0r({
                connection,
                issuer: 'test',
                private_key: '',
                public_key: '',
                user_identifier: 'username',
            });
            // need to create dummy user data
            const dummy = { username: 'testy', password: 'Password1*' };
            let result;
            chai_1.expect(result = yield auth0r.tryRegister(dummy.username, dummy.password)).to.not.throw;
            chai_1.expect(result).to.equal(dummy.username);
            const knex = knex_1.default(connection);
            let users;
            chai_1.expect(users = yield knex.table('Users')
                .select()).to.not.throw;
            chai_1.expect(users).has.length(1);
            const user_data = users[0];
            chai_1.expect(user_data).has.keys(['id', 'username', 'password', 'o']);
            chai_1.expect(user_data.id).is.a('number');
            chai_1.expect(user_data.username).to.equal(dummy.username);
            chai_1.expect(bcrypt_1.default.compareSync(dummy.password, user_data.password)).to.be.true;
            chai_1.expect(user_data.o).to.be.null;
        });
    });
    it('should return an opaque key and jwt when logging in', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const auth0r = new src_1.Auth0r({
                connection,
                issuer: 'test',
            });
            // Database made, lets create user manually
            const password = 'Password1*';
            const email = 'test@test.com';
            const hash = bcrypt_1.default.hashSync(password, 12);
            const knex = knex_1.default(connection);
            chai_1.expect(yield knex.table('Users')
                .insert({ email, password: hash })).to.not.throw;
            // User created, let try logging in
            let jwtoken;
            const request = {
                body: {
                    o: '',
                },
            };
            chai_1.expect(jwtoken = yield auth0r.tryLogin(email, password)).to.not.throw;
            const { o: opaque } = jwt.decode(jwtoken);
            let user_data;
            chai_1.expect(user_data = yield knex.table('Users').select('id', 'o').where('email', email)).to.not.throw;
            const id_num = user_data[0].id;
            let dbOpaque = user_data[0].o;
            chai_1.expect(dbOpaque).to.equal(opaque);
            chai_1.expect(typeof opaque === 'string').to.be.true;
            chai_1.expect(opaque.length).to.equal(32);
            chai_1.expect(yield auth0r.verifyToken(id_num, jwtoken, request)).to.be.true;
            chai_1.expect(request.body.o).has.length(32);
            chai_1.expect(dbOpaque = yield knex.table('Users').select('o').where('email', email)).to.not.throw;
            dbOpaque = dbOpaque[0].o;
            chai_1.expect(dbOpaque).to.equal(request.body.o);
        });
    });
    it('should intercept unauthorized traffic and result in 403', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const test = (token) => __awaiter(this, void 0, void 0, function* () {
                const auth0r = new src_1.Auth0r({
                    connection,
                    issuer: 'test',
                });
                const request = {
                    headers: {
                        authorization: token,
                    },
                    user: undefined,
                };
                const response = new MiddlewareResponse_1.MiddlewareResponse();
                const next = new MiddlewareNext_1.MiddlewareNext();
                chai_1.expect(yield auth0r.middleware(request, response, () => next.run(request, response))).to.not.throw;
                return { request, response, next };
            });
            const { request: req_null, response: res_null, next: next_null } = yield test(null);
            chai_1.expect(next_null.ran).to.be.true;
            chai_1.expect(res_null.response).to.be.undefined;
            chai_1.expect(req_null.user).to.be.undefined;
            const { response: res_blank, next: next_blank } = yield test('');
            chai_1.expect(next_blank.ran).to.be.false;
            chai_1.expect(res_blank.response).to.equal(401);
            const { response: res_invalid, next: next_invalid } = yield test('INVALID');
            chai_1.expect(next_invalid.ran).to.be.false;
            chai_1.expect(res_invalid.response).to.equal(401);
        });
    });
    it('should allow authorized traffic and return with new opaque key', function () {
        return __awaiter(this, void 0, void 0, function* () {
            const auth0r = new src_1.Auth0r({
                connection,
                issuer: 'test',
                user_identifier: 'username',
            });
            const knex = knex_1.default(connection);
            chai_1.expect(yield knex.table('Users')
                .insert({
                password: bcrypt_1.hashSync('Password1*', 12),
                username: 'test',
            })).to.not.throw;
            let user_id;
            chai_1.expect(user_id = (yield knex.table('Users').select('id').where('username', 'test'))[0].id).to.not.throw;
            let valid_jwt;
            chai_1.expect(valid_jwt = yield auth0r.tryLogin('test', 'Password1*')).to.not.throw;
            const request = {
                headers: {
                    authorization: `Bearer: ${valid_jwt}:${user_id}`,
                },
                user: undefined,
            };
            const response = new MiddlewareResponse_1.MiddlewareResponse();
            const next = new MiddlewareNext_1.MiddlewareNext();
            chai_1.expect(yield auth0r.middleware(request, response, () => next.run(request, response))).to.not.throw;
            chai_1.expect(next.ran).to.be.true;
            chai_1.expect(request.user).to.not.be.undefined;
            chai_1.expect(request.user).to.equal(user_id);
        });
    });
    after(function () {
        return __awaiter(this, void 0, void 0, function* () {
            deleteTestDatabase();
        });
    });
});
function deleteTestDatabase() {
    Utilities_1.log(`Deleting ${test_db.toString()}`);
    if (fs_1.default.existsSync(test_db)) {
        Utilities_1.log('database already exists ... deleting');
        fs_1.default.unlinkSync(test_db);
    }
}
function deleteRSAKeys() {
    rimraf(key_folder);
}
function newTestDatabase() {
    Utilities_1.log(`Copying ${test_db_empty.toString()} > ${test_db.toString()}`);
    fs_1.default.copyFileSync(test_db_empty, test_db);
    Utilities_1.log(fs_1.default.existsSync(test_db) ? 'Database now exists!' : 'Database does not exist');
    return test_db;
}
/**
 * Remove directory recursively
 * @param {string} dir_path
 * @see https://stackoverflow.com/a/42505874/3027390
 */
function rimraf(dir_path) {
    if (fs_1.default.existsSync(dir_path)) {
        fs_1.default.readdirSync(dir_path).forEach(function (entry) {
            const entry_path = path_1.default.join(dir_path, entry);
            if (fs_1.default.lstatSync(entry_path).isDirectory()) {
                rimraf(entry_path);
            }
            else {
                fs_1.default.unlinkSync(entry_path);
            }
        });
        fs_1.default.rmdirSync(dir_path);
    }
}
//# sourceMappingURL=auth.spec.js.map