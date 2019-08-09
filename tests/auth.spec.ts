import {expect} from "chai";
import { Auth0r } from "../src";
import { fail } from "assert";
import fs from 'fs';
import path from 'path';
import {log, error} from "../src/Utilities/Utilities";
import Knex from 'knex';
import bcrypt, {hashSync} from 'bcrypt';
import crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

let dir = __dirname;

const test_db = path.resolve(dir, './test.db');
const test_db_empty = path.resolve(dir, './test_empty.db');
const key_folder = path.resolve(__dirname, '../rsa_keys');

describe('Auth0r StartUp Suite', function() {
	const connection = test_db;

	before(async function() {
		deleteRSAKeys();
		expect(fs.existsSync(key_folder)).to.be.false;
	});
	beforeEach(function() {
		// delete old database
		process.env.NODE_ENV="development";
		newTestDatabase();
	});
	it('should generate RSA tokens if none exist', function() {
		let equal_instances = [
			new Auth0r({
				issuer: 'test',
				user_identifier: 'username',
				connection
			}),
			new Auth0r({
				issuer: 'test',
				user_identifier: 'username',
				public_key: 'df',
				connection
			}),
			new Auth0r({
				issuer: 'test',
				user_identifier: 'username',
				private_key: 'sdfg',
				connection
			}),
			new Auth0r({
				issuer: 'test',
				user_identifier: 'username',
				private_key: 'fasf',
				public_key: 'asdf',
				connection
			}),
			new Auth0r({
				issuer: 'test',
				user_identifier: 'username',
				private_key: '',
				public_key: '',
				connection
			}),
			new Auth0r({
				issuer: 'test',
				user_identifier: 'email',
				private_key: path.resolve(dir, './test_rsa_invalid/privkey.pem'),
				public_key: path.resolve(dir, './test_rsa_invalid/privkey.pem'),
				connection
			}),
			new Auth0r({
				issuer: 'test',
				user_identifier: 'email',
				private_key: path.resolve(dir, './test_rsa_empty/privkey.pem'),
				public_key: path.resolve(dir, './test_rsa_empty/privkey.pem'),
				connection
			})
		];
		let compareFn;
		for (let x of equal_instances) {
			if (compareFn != undefined) {
				expect(compareFn(x)).to.be.true;
			}
			compareFn = (y) => Auth0r.compareKeyTwins(x, y);
		}
		expect(fs.existsSync(key_folder)).to.be.true;
		let keys = {
			public_key:  path.resolve(__dirname, '../rsa_keys/pubkey.pem'),
			private_key:  path.resolve(__dirname, '../rsa_keys/privkey.pem')
		};
		expect(fs.existsSync(keys.public_key)).to.be.true;
		expect(fs.existsSync(keys.private_key)).to.be.true;
		for (let key of Object.keys(keys)) {
			let contents = fs.readFileSync(keys[key], { encoding: 'utf-8' });
			expect(crypto[key === "private_key" ? "createPrivateKey" : "createPublicKey"](contents)).to.not.throw;
		}
	});
	it('should use provided RSA token files', async function() {
		let pub_key = path.resolve(__dirname, './test_rsa_valid/pubkey.pem');
		let priv_key = path.resolve(__dirname, './test_rsa_valid/privkey.pem');
		let auth0r = new Auth0r({
			issuer: '',
			user_identifier: 'username',
			connection,
			public_key: pub_key,
			private_key: priv_key
		});
		let pub_contents = fs.readFileSync(pub_key, { encoding: "UTF-8" });
		let priv_contents = fs.readFileSync(pub_key, { encoding: "UTF-8" });
		expect(Auth0r.compareKeys(auth0r, pub_contents, priv_contents));
	});
	it('should use provided rsa key strings', async function() {
		let pub_key = path.resolve(__dirname, './test_rsa_valid/pubkey.pem');
		let priv_key = path.resolve(__dirname, './test_rsa_valid/privkey.pem');
		let pub_contents = fs.readFileSync(pub_key, { encoding: "UTF-8" });
		let priv_contents = fs.readFileSync(priv_key, { encoding: "UTF-8" });
		let auth0r = new Auth0r({
			issuer: '',
			user_identifier: 'username',
			connection,
			public_key: pub_contents,
			private_key: priv_contents
		});
		expect(Auth0r.compareKeys(auth0r, pub_contents, priv_contents));
	});
	it('should generate a random opaque key', function() {
		let hashMap = {};
		console.log("Example opaque key: %s", Auth0r.generateOpaqueKey());
		for (let x = 0; x < 10000; ++x) {
			let randomKey = Auth0r.generateOpaqueKey();
			if (randomKey.length !== 32) {
				fail(`Random opaque key length invalid!  (length: ${randomKey.length})`);
			}
			if (hashMap[randomKey]) {
				fail("Random Opaque key collision detected!");
			}
			hashMap[randomKey] = true;
		}
		expect(Object.keys(hashMap)).to.have.length(10000);
	});
	it('should initialize database and function well', async function() {
		let auth0r = new Auth0r({
			issuer: 'test',
			public_key: '',
			private_key: '',
			user_identifier: 'username',
			connection
		});

		expect(auth0r.dbReady).to.be.true;
		let knex = Knex(connection);

		let schema = {
			Users: {
				columns: [
					{
						name: 'id',
						type: 'number',
						primary_key: true,
						test_value: ''
					},
					{
						name: 'username',
						type: 'string',
						primary_key: false,
						test_value: 'username'
					},
					{
						name: 'password',
						type: 'string',
						primary_key: false,
						test_value: bcrypt.hashSync('Password1*', 12)
					},
					{
						name: 'o',
						type: 'string',
						primary_key: false,
						test_value: '9smMseYnhRy7t5spnUtsb7ACX3SREIKg'
					}
				]
			},
			Auth0r_Log: {
				columns: [
					{
						name: 'id',
						type: 'number',
						primary_key: true,
						test_value: ''
					},
					{
						name: 'identifier',
						type: 'string',
						primary_key: false,
						test_value: 'IDENTIFIER'
					},
					{
						name: 'prod_error',
						type: 'string',
						primary_key: false,
						test_value: 'PROD_ERROR'
					},
					{
						name: 'dev_error',
						type: 'string',
						primary_key: false,
						test_value: 'DEV_ERROR'
					},
					{
						name: 'message',
						type: 'string',
						primary_key: false,
						test_value: 'MESSAGE - MESSAGE'
					}
				]
			}
		};

		for (let tableName of Object.keys(schema)) {
			expect(await knex.schema.hasTable(tableName)).to.be.true;

			let columns = schema[tableName].columns;
			let insertValues = {};
			for (let column of columns) {
				expect(await knex.schema.hasColumn(tableName, column.name)).to.be.true;
				if (!column.primary_key) {
					insertValues[column.name] = column.test_value;
				}
			}

			try {
				let insertResult = await knex.table(tableName).insert(insertValues);
				expect(insertResult.length).to.equal(1);
				expect(insertResult[0]).to.equal(1);
			} catch (err) {
				error(err);
				fail(`Failed to insert test values into table! [Table: ${tableName}]`);
			}
			let results = await knex.table(tableName).select('*');
			expect(results.length).to.equal(1);
			expect(Object.keys(results[0]).length).to.equal(columns.length);
			for (let column of columns) {
				expect(results[0][column.name]).is.a(column.type);
				if (!column.primary_key) {
					expect(results[0][column.name]).to.equal(column.test_value);
				}
			}
		}
	});
	it('should create a new user when registering', async function() {
		let auth0r = new Auth0r({
			issuer: 'test',
			public_key: '',
			private_key: '',
			user_identifier: 'username',
			connection
		});
		// need to create dummy user data
		let dummy = { username: 'testy', password: 'Password1*' };

		let result;
		expect(result = await auth0r.tryRegister(dummy.username, dummy.password)).to.not.throw;

		expect(result).to.equal(dummy.username);

		let knex = Knex(connection);
		let users;
		expect(users = await knex.table('Users')
			.select()).to.not.throw;

		expect(users).has.length(1);
		let user_data = users[0];
		expect(user_data).has.keys(['id', 'username', 'password', 'o']);
		expect(user_data.id).is.a('number');
		expect(user_data.username).to.equal(dummy.username);
		expect(bcrypt.compareSync(dummy.password, user_data.password)).to.be.true;
		expect(user_data.o).to.be.null;
	});
	it('should return an opaque key and jwt when logging in', async function() {
		let auth0r = new Auth0r({
			issuer: 'test',
			connection
		});
		// Database made, lets create user manually
		let password = "Password1*";
		let email = 'test@test.com';

		let hash = bcrypt.hashSync(password, 12);
		let knex = Knex(connection);
		expect(await knex.table('Users')
			.insert({ email, password: hash })).to.not.throw;

		// User created, let try logging in
		let jwtoken;
		let request = {
			body: {
				o: ''
			}
		};
		expect(jwtoken = await auth0r.tryLogin(email, password)).to.not.throw;
		let { o: opaque } = jwt.decode(jwtoken);
		let user_data;
		expect(user_data = await knex.table('Users').select('id', 'o').where('email', email)).to.not.throw;
		let id_num = user_data[0].id;
		let dbOpaque = user_data[0].o;

		expect(dbOpaque).to.equal(opaque);

		expect(typeof opaque === "string").to.be.true;
		expect(opaque.length).to.equal(32);


		expect(await auth0r.verifyToken(id_num, jwtoken, request)).to.be.true;
		expect(request.body.o).has.length(32);
		expect(dbOpaque = await knex.table('Users').select('o').where('email', email)).to.not.throw;
		dbOpaque = dbOpaque[0].o;
		expect(dbOpaque).to.equal(request.body.o);
	});
	it('should intercept unauthorized traffic and result in 403', async function() {
		let test = async (jwt) => {
			let auth0r = new Auth0r({
				issuer: 'test',
				connection
			});
			let request = {
				headers: {
					authorization: jwt
				},
                user: undefined
			};
			let response = new MiddlewareResponse();
			let next = new MiddlewareNext();

			expect(await auth0r.middleware(request, response, () => next.run(request, response))).to.not.throw;
			return {request, response, next};
		};

		let { request: req_null,  response: res_null, next: next_null } = await test(null);
		let { response: res_blank, next: next_blank } = await test('');
		let { response: res_invalid, next: next_invalid } = await test('INVALID');

		expect(next_null.ran).to.be.true;
		expect(next_blank.ran).to.be.false;
		expect(next_invalid.ran).to.be.false;
		expect(res_null.response).to.be.undefined;
		expect(req_null.user).to.be.undefined;
		expect(res_blank.response).to.equal(401);
		expect(res_invalid.response).to.equal(401);
	});
	it('should allow authorized traffic and return with new opaque key', async function() {
		let auth0r = new Auth0r({
			issuer: 'test',
			user_identifier: 'username',
			connection
		});

		let knex = Knex(connection);
		expect(await knex.table('Users')
			.insert({
				username: 'test',
				password: hashSync('Password1*', 12)
			})).to.not.throw;
		let user_id;
		expect(user_id = (await knex.table('Users').select('id').where('username', 'test'))[0].id).to.not.throw;
		let valid_jwt;
		expect(valid_jwt = await auth0r.tryLogin('test', 'Password1*')).to.not.throw;
		let request = {
			headers: {
				authorization: `Bearer: ${valid_jwt}:${user_id}`
			},
			user: undefined
		};
		let response = new MiddlewareResponse();
		let next = new MiddlewareNext();

		expect(await auth0r.middleware(request, response, () => next.run(request, response))).to.not.throw;

		expect(next.ran).to.be.true;
		expect(request.user).to.not.be.undefined;
		expect(request.user).to.equal(user_id);
	});
	after(async function() {
		deleteTestDatabase();
	});
});

function deleteTestDatabase() {
	log(`Deleting ${test_db.toString()}`);
	if (fs.existsSync(test_db)) {
		log('database already exists ... deleting');
		fs.unlinkSync(test_db);
	}
}

function deleteRSAKeys() {
	rimraf(key_folder);
}

function newTestDatabase() {
	log(`Copying ${test_db_empty.toString()} > ${test_db.toString()}`);
	fs.copyFileSync(test_db_empty, test_db);
	log(fs.existsSync(test_db) ? 'Database now exists!' : 'Database does not exist');
	return test_db;
}

class MiddlewareResponse {
	public response: any;
	public sendStatus = this.send;
	send(response) {
		this.response = response;
	}
}

class MiddlewareNext {
	public ran: boolean;

	constructor() {
		this.ran = false;
	}

	run(req, res) {
		this.ran = true;
		expect(req).to.not.be.undefined;
		expect(res).to.not.be.undefined;
	}
}

/**
 * Remove directory recursively
 * @param {string} dir_path
 * @see https://stackoverflow.com/a/42505874/3027390
 */
function rimraf(dir_path) {
	if (fs.existsSync(dir_path)) {
		fs.readdirSync(dir_path).forEach(function(entry) {
			let entry_path = path.join(dir_path, entry);
			if (fs.lstatSync(entry_path).isDirectory()) {
				rimraf(entry_path);
			} else {
				fs.unlinkSync(entry_path);
			}
		});
		fs.rmdirSync(dir_path);
	}
}
