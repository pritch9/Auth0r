import {expect, should, assert} from "chai";
import { Auth0r } from "../src";
import { fail } from "assert";
import fs from 'fs';
import path from 'path';
import {log, error} from "../src/Utilities/Utilities";
import Knex from 'knex';
import bcrypt from 'bcrypt';

let dir = __dirname;

describe('Auth0r Test Suite', function() {
	let connection: any;

	before(function() {
		rimraf(path.resolve(__dirname, '../rsa_keys'));
	});
	beforeEach(function() {
		// delete old database
		process.env.NODE_ENV="development";
		connection = newTestDatabase();
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
	it('should create a new user when registering', function() {
		let auth0r = new Auth0r({
			issuer: 'test',
			public_key: '',
			private_key: '',
			connection
		});
	});
});

function newTestDatabase() {
	let test_empty = path.resolve(dir, './test_empty.db');
	let test = path.resolve(dir, './test.db');
	log(`Deleting ${test.toString()}`);
	if (fs.existsSync(test)) {
		log('database already exists ... deleting');
		fs.unlinkSync(test);
	}
	log(`Copying ${test_empty.toString()} > ${test.toString()}`);
	fs.copyFileSync(test_empty, test);
	log(fs.existsSync(test) ? 'Database now exists!' : 'Database does not exist');
	return test;
}/**
 * Remove directory recursively
 * @param {string} dir_path
 * @see https://stackoverflow.com/a/42505874/3027390
 */
function rimraf(dir_path) {
	if (fs.existsSync(dir_path)) {
		fs.readdirSync(dir_path).forEach(function(entry) {
			var entry_path = path.join(dir_path, entry);
			if (fs.lstatSync(entry_path).isDirectory()) {
				rimraf(entry_path);
			} else {
				fs.unlinkSync(entry_path);
			}
		});
		fs.rmdirSync(dir_path);
	}
}
