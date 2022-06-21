import {fail} from 'assert';
import * as bcrypt from 'bcrypt';
import {expect} from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';
import Knex from 'knex';
import * as path from 'path';
import {Auth0r} from '../src';
import {error, log} from '../src/Utilities/Utilities';
import {MiddlewareNext} from './Models/MiddlewareNext';
import {MiddlewareResponse} from './Models/MiddlewareResponse';

const dir = __dirname;

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
		process.env.NODE_ENV = 'development';
		newTestDatabase();
	});
	it('should generate RSA tokens if none exist', function() {
		const equal_instances = [
			new Auth0r({
				connection,
				issuer: 'test',
				user_identifier: 'username',
			}),
			new Auth0r({
				connection,
				issuer: 'test',
				public_key: 'df',
				user_identifier: 'username',
			}),
			new Auth0r({
				connection,
				issuer: 'test',
				private_key: 'sdfg',
				user_identifier: 'username',
			}),
			new Auth0r({
				connection,
				issuer: 'test',
				private_key: 'fasf',
				public_key: 'asdf',
				user_identifier: 'username',
			}),
			new Auth0r({
				connection,
				issuer: 'test',
				private_key: '',
				public_key: '',
				user_identifier: 'username',
			}),
			new Auth0r({
				connection,
				issuer: 'test',
				private_key: path.resolve(dir, './test_rsa_invalid/privkey.pem'),
				public_key: path.resolve(dir, './test_rsa_invalid/privkey.pem'),
				user_identifier: 'email',
			}),
			new Auth0r({
				connection,
				issuer: 'test',
				private_key: path.resolve(dir, './test_rsa_empty/privkey.pem'),
				public_key: path.resolve(dir, './test_rsa_empty/privkey.pem'),
				user_identifier: 'email',
			}),
		];
		let compareFn;
		for (const x of equal_instances) {
			if (compareFn !== undefined) {
				expect(compareFn(x)).to.be.true;
			}
			compareFn = (y) => Auth0r.compareKeyTwins(x, y);
		}
		expect(fs.existsSync(key_folder)).to.be.true;
		const keys = {
			private_key: path.resolve(__dirname, '../rsa_keys/privkey.pem'),
			public_key: path.resolve(__dirname, '../rsa_keys/pubkey.pem'),
		};
		expect(fs.existsSync(keys.public_key)).to.be.true;
		expect(fs.existsSync(keys.private_key)).to.be.true;
		for (const key of Object.keys(keys)) {
			const contents = fs.readFileSync(keys[key], {encoding: 'utf-8'});
			expect(crypto[key === 'private_key' ? 'createPrivateKey' : 'createPublicKey'](contents)).to.not.throw;
		}
	});
	it('should use provided RSA token files', async function() {
		const pub_key = path.resolve(__dirname, './test_rsa_valid/pubkey.pem');
		const priv_key = path.resolve(__dirname, './test_rsa_valid/privkey.pem');
		const auth0r = new Auth0r({
			connection,
			issuer: '',
			private_key: priv_key,
			public_key: pub_key,
			user_identifier: 'username',
		});
		const pub_contents = fs.readFileSync(pub_key, {encoding: 'utf-8'});
		const priv_contents = fs.readFileSync(pub_key, {encoding: 'utf-8'});
		expect(Auth0r.compareKeys(auth0r, pub_contents, priv_contents));
	});
	it('should use provided rsa key strings', async function() {
		const pub_key = path.resolve(__dirname, './test_rsa_valid/pubkey.pem');
		const priv_key = path.resolve(__dirname, './test_rsa_valid/privkey.pem');
		const pub_contents = fs.readFileSync(pub_key, {encoding: 'utf-8'});
		const priv_contents = fs.readFileSync(priv_key, {encoding: 'utf-8'});
		const auth0r = new Auth0r({
			connection,
			issuer: '',
			private_key: priv_contents,
			public_key: pub_contents,
			user_identifier: 'username',
		});
		expect(Auth0r.compareKeys(auth0r, pub_contents, priv_contents));
	});
	it('should generate a random opaque key', function() {
		const hashMap = {};
		console.log('Example opaque key: %s', Auth0r.generateOpaqueKey());
		for (let x = 0; x < 10000; ++x) {
			const randomKey = Auth0r.generateOpaqueKey();
			if (randomKey.length !== 32) {
				fail(`Random opaque key length invalid!  (length: ${randomKey.length})`);
			}
			if (hashMap[randomKey]) {
				fail('Random Opaque key collision detected!');
			}
			hashMap[randomKey] = true;
		}
		expect(Object.keys(hashMap)).to.have.length(10000);
	});
	it('should initialize database and function well', async function() {
		const auth0r = new Auth0r({
			connection,
			issuer: 'test',
			private_key: '',
			public_key: '',
			user_identifier: 'username',
		});

		expect(auth0r.dbReady).to.be.true;
		const knex = Knex(connection);

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
						test_value: bcrypt.hashSync('Password1*', 12),
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
			Auth0r_Admins: {
				columns: [
					{
						name: 'user_id',
						primary_key: false,
						test_value: 1,
						type: 'number',
					},
				],
			},
		};

		for (const tableName of Object.keys(schema)) {
			expect(await knex.schema.hasTable(tableName)).to.be.true;

			const columns = schema[tableName].columns;
			const insertValues = {};
			for (const column of columns) {
				expect(await knex.schema.hasColumn(tableName, column.name)).to.be.true;
				if (!column.primary_key) {
					insertValues[column.name] = column.test_value;
				}
			}

			try {
				const insertResult = await knex.table(tableName).insert(insertValues);
				expect(insertResult.length).to.equal(1);
				expect(insertResult[0]).to.equal(1);
			} catch (err) {
				error(err);
				fail(`Failed to insert test values into table! [Table: ${tableName}]`);
			}
			const results = await knex.table(tableName).select('*');
			expect(results.length).to.equal(1);
			expect(Object.keys(results[0]).length).to.equal(columns.length);
			for (const column of columns) {
				switch (column.type) {
					case 'date':
						if (column.type === 'Date') {
							const dbDate = new Date(results[0][column.name]);
							expect(dbDate.getTime()).to.be.equal(column.test_value.getTime());
						}
						break;
					case 'string':
						expect(results[0][column.name]).is.a('string');
						break;
					default:
						continue;
				}
				if (!column.primary_key) {
					expect(results[0][column.name]).to.equal(column.test_value);
				}
			}
		}
	});
	it('should create a new user when registering', async function() {
		const auth0r = new Auth0r({
			connection,
			issuer: 'test',
			private_key: '',
			public_key: '',
			user_identifier: 'username',
		});
		// need to create dummy user data
		const dummy = {username: 'testy', password: 'Password1*'};

		let result;
		expect(result = await auth0r.tryRegister(dummy.username, dummy.password)).to.not.throw;

		expect(result).to.equal(dummy.username);

		const knex = Knex(connection);
		let users;
		expect(users = await knex.table('Users')
			.select()).to.not.throw;

		expect(users).has.length(1);
		const user_data = users[0];
		expect(user_data).has.keys(['id', 'username', 'password', 'o']);
		expect(user_data.id).is.a('number');
		expect(user_data.username).to.equal(dummy.username);
		expect(bcrypt.compareSync(dummy.password, user_data.password)).to.be.true;
		expect(user_data.o).to.be.null;
	});
	it('should return an opaque key and jwt when logging in', async function() {
		const auth0r = new Auth0r({
			connection,
			issuer: 'test',
		});
		// Database made, lets create user manually
		const password = 'Password1*';
		const email = 'test@test.com';

		const hash = bcrypt.hashSync(password, 12);
		const knex = Knex(connection);
		expect(await knex.table('Users')
			.insert({email, password: hash})).to.not.throw;

		// User created, let try logging in
		let jwtoken;
		const request = {
			body: {
				o: '',
			},
		};
		expect(jwtoken = await auth0r.tryLogin(email, password)).to.not.throw;
		const {o: opaque} = jwt.decode(jwtoken);
		let user_data;
		expect(user_data = await knex.table('Users').select('id', 'o').where('email', email)).to.not.throw;
		const id_num = user_data[0].id;
		let dbOpaque = user_data[0].o;

		expect(dbOpaque).to.equal(opaque);

		expect(typeof opaque === 'string').to.be.true;
		expect(opaque.length).to.equal(32);

		expect(await auth0r.verifyToken(id_num, jwtoken, request)).to.be.true;
		expect(request.body.o).has.length(32);
		expect(dbOpaque = await knex.table('Users').select('o').where('email', email)).to.not.throw;
		dbOpaque = dbOpaque[0].o;
		expect(dbOpaque).to.equal(request.body.o);
	});

	it('should intercept traffic for null token', async function() {
		const {request: req_null, response: res_null, next: next_null} = await basicTokenTest(connection, null);
		expect(next_null.ran).to.be.false;
		expect(req_null.user).to.be.undefined;
		expect(res_null.response).to.be.equal(401);
	});

	it('should intercept traffic for blank token', async function() {
		const {request: req_null, response: res_null, next: next_null} = await basicTokenTest(connection, '');
		expect(next_null.ran).to.be.false;
		expect(req_null.user).to.be.undefined;
		expect(res_null.response).to.be.equal(401);
	});

	it('should intercept traffic for invalid token', async function() {
		const {request: req_null, response: res_null, next: next_null} = await basicTokenTest(connection, 'INVALID');
		expect(next_null.ran).to.be.false;
		expect(req_null.user).to.be.undefined;
		expect(res_null.response).to.be.equal(401);
	});

	it('should allow authorized traffic and return with new opaque key', async function() {
		this.timeout(5000);
		const auth0r = new Auth0r({
			connection,
			issuer: 'test',
			user_identifier: 'username',
		});

		const knex = Knex(connection);
		expect(await knex.table('Users')
			.insert({
				password: bcrypt.hashSync('Password1*', 12),
				username: 'test',
			})).to.not.throw;
		let user_id;
		expect(user_id = (await knex.table('Users').select('id').where('username', 'test'))[0].id).to.not.throw;
		let valid_jwt;
		expect(valid_jwt = await auth0r.tryLogin('test', 'Password1*')).to.not.throw;
		const request = {
			headers: {
				authorization: `Bearer: ${valid_jwt}:${user_id}`,
			},
			user: undefined,
		};
		const response = new MiddlewareResponse();
		const next = new MiddlewareNext();

		expect(await auth0r.middleware(request, response, () => next.run(request, response))).to.not.throw;

		expect(next.ran).to.be.true;
		expect(request.user).to.not.be.undefined;
		expect(request.user).to.equal(user_id);
	});
	after(function() {
		deleteTestDatabase();
	});
});

async function basicTokenTest(connection: any, token: string | null | undefined) {
	const auth0r = new Auth0r({
		connection,
		issuer: 'test',
	});
	const request = {
		headers: {
			authorization: token,
		},
		user: undefined,
	};
	const response = new MiddlewareResponse();
	const next = new MiddlewareNext();

	log(`Before middleware: ${token}`);
	expect(await auth0r.middleware(request, response, () => next.run(request, response))).to.not.throw;
	log(`After middleware: ${token}`);
	return {request, response, next};
}

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

/**
 * Remove directory recursively
 * @param {string} dir_path
 * @see https://stackoverflow.com/a/42505874/3027390
 */
function rimraf(dir_path) {
	if (fs.existsSync(dir_path)) {
		fs.readdirSync(dir_path).forEach(function(entry) {
			const entry_path = path.join(dir_path, entry);
			if (fs.lstatSync(entry_path).isDirectory()) {
				rimraf(entry_path);
			} else {
				fs.unlinkSync(entry_path);
			}
		});
		fs.rmdirSync(dir_path);
	}
}
