import {expect} from 'chai';
import express, {Application} from 'express';
import Knex from 'knex';
import Auth0r from '../src';
import Auth0rConfig, {Auth0rConfiguration} from '../src/Models/Auth0rConfig';
import 'mocha';
import Indexed from '../src/Models/Indexed';
import Config from '../src/Models/Config';
import * as WebRequest from 'web-request';
import {Server} from 'http';
import { compare, hash } from 'bcrypt';
import base64url from 'base64url';
import Util from 'util';

const fs = require('fs').promises;
const path = require('path');

const test_db = path.resolve(__dirname, './database/test.db');

let hasher = Util.promisify(hash);
let comparer = Util.promisify(compare);

describe('Auth0r Test Suite', function() {
	this.bail();
	let app: Application;
	let server: Server;
	let testDBConnection = {
		client: 'sqlite3',
		connection: path.resolve(__dirname, './database/test.db'),
		useNullAsDefault: true
	};

	let default_config: Auth0rConfiguration = Auth0rConfig({
		database: testDBConnection,
		public_key: '',
		private_key: ''
	});

	before(function() {
		process.env.NODE_ENV = 'test';
	});

	after(async function() {await cleanDatabase(false);});

	beforeEach(async function() {
		app = createTestServer();
		server = app.listen(8080);

		await cleanDatabase();
	});

	afterEach(function(done) {
		server.close(done);
	});

	it('should automatically load defaults to config', function() {
		let aConf = Auth0rConfig();
		expect(aConf).has.property('database');
		expect(aConf).has.property('app_name');
		expect(aConf.database).to.deep.equal({client: 'sqlite3', connection: './database/Auth0rDefault.db'});
		expect(aConf.app_name).to.equal('Auth0r');

		let test_defaults = {
			key1: 'value1',
			key2: {
				value: '1'
			}
		};

		let config = new Config({}, test_defaults);
		expect(config).to.have.property('key1');
		expect(config).to.have.property('key2');
		expect(config.key1).to.equal('value1');
		expect(config.key2).to.deep.equal({value: '1'});

		config = new Config({key1: 'new_value', key2: 'forgetaboutit', key3: 'woop woop'}, test_defaults);
		expect(config).to.have.property('key1');
		expect(config).to.have.property('key2');
		expect(config).to.have.property('key3');
		expect(config.key1).to.equal('new_value');
		expect(config.key2).to.equal('forgetaboutit');
		expect(config.key3).to.equal('woop woop');
	});

	it('should have correct databases after initialization', async function() {
		let options = Auth0rConfig({
			database: testDBConnection,
			app_name: 'Test1'
		});

		expect(await Auth0r.initialize(app, options)).to.not.throw;

		let knex = Knex(testDBConnection);

		expect(await knex.schema.hasTable('Users')).to.be.true;
		expect(await knex.schema.hasTable('Admini5trators')).to.be.true;
		expect(await knex.schema.hasTable('Auth0rLog')).to.be.true;
	});

	it('should allow access to Auth0rAdmin endpoints', async function() {
		await Auth0r.initialize(app, default_config);
		let endpoints = Indexed({
			'POST': [
				'/auth/login',
				'/account/register',
				'/admin/auth/login'
			]
		});

		for (let method of Object.keys(endpoints)) {
			for (let url of endpoints[method]) {
				it(`should allow ${method} to endpoint ${url}`, async function() {
					this.timeout(1000);
					let result;
					expect(result = await WebRequest.post(`http://localhost:8080${url}`)).to.not.throw;
					expect(result.statusCode).to.not.equal(404, `[${method}] to ${url} is anything but 404`);
				});
			}
		}
	});

	it('generates rsa keys when prompted without them', async function() {

	});

	it('registers a new user when a valid request is made', async function() {
		// this.retries(3);
		this.timeout(1500);
		await Auth0r.initialize(app, default_config);

		let endpoint = 'http://localhost:8080/account/register';

		let dummy_account = {
			identifier: "TEST_USER",
			password: 'H3ll0W0rld'
		};

		let result;
		expect(result = (await WebRequest.post(endpoint, { json: true }, dummy_account)).content).to.not.throw;

		expect(result).to.equal(dummy_account.identifier);

		let knex = Knex(testDBConnection);

		let hash;
		expect(hash = (await knex.table('Users').select('password').where('identifier', result))[0].password)
			.to.not.throw;

		expect(await comparer(dummy_account.password, hash)).to.be.true;
	});

	it('should allow a user to login', async function() {
		// this.retries(3);
		this.timeout(1500);
		await Auth0r.initialize(app, default_config);
		let endpoint = 'http://localhost:8080/auth/login';

		let knex = Knex(testDBConnection);
		let { identifier, hash_password, plaintext } = {
			identifier: 'dummy_user',
			hash_password: await hasher('FakePassword1', 12),
			plaintext: 'FakePassword1'
		};

		expect(await knex.table('Users').insert( { identifier, password: hash_password })).to.not.throw;

		let response: any;
		expect(response = await WebRequest.post(endpoint, { json: true }, { identifier, password: plaintext })
		).to.not.throw;

		expect(response).to.have.property('body');

		response = response.body;

		expect(response).to.have.property('token');
		expect(response).to.have.property('opaque');

		expect(response.opaque).to.have.length(32);

		let [headers, payload] = response.token.split('.');

		expect(headers = JSON.parse(base64url.decode(headers, 'utf-8'))).to.not.throw;
		expect(payload = JSON.parse(base64url.decode(payload, 'utf-8'))).to.not.throw;

		expect(headers).to.have.property('alg', 'RS256');

		expect(payload.admin).to.be.false;
		expect(payload.id).to.be.greaterThan(0);
		expect(payload.aud).to.equal(identifier);

		let dbOpaque;
		expect(dbOpaque = (await knex.table('Users').select('opaque').where({ id: payload.id }))[0].opaque).to.not.throw;
		expect(dbOpaque).to.equal(response.opaque);

		// successful login if i do say so myself
	});
});

async function cleanDatabase(restore: boolean = true) {
	console.warn('Clearing database...');
	const clean_db = path.resolve(__dirname, './database/clean/clean.db');
	await fs.unlink(test_db);
	if (restore) { await fs.copyFile(clean_db, test_db) }
}

function createTestServer(): Application {
	let app = express();

	app.use(require('cors')());
	app.use(express.json());

	return app;
}
