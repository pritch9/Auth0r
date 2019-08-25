import Knex = require('knex');
import { expect } from 'chai';
import {TableBuilder} from 'knex';
import Indexed from '../../Models/Indexed';

export default class DBInitializer {
	static knex: Knex;
	private static _ready = false;

	public static get ready() { return DBInitializer._ready; }
	private static done_initializing() { DBInitializer._ready = true; }

	static async initializeDatabase(database: any) {
		try {
			DBInitializer.knex = Knex(database);
			await DBInitializer.knex.raw('SELECT 1+1 AS result');
		} catch (err) {
			throw new Error(`Unable to connect to database! ${err.message}`);
		}

		if (!await DBInitializer.checkDatabaseExistence()) {
			await DBInitializer.createDatabase();
		}

		DBInitializer.done_initializing();
	}

	private static async checkDatabaseExistence() {
		let knex = DBInitializer.knex;
		try {
			expect(await knex.schema.hasTable('Users')).to.be.true;
			expect(await knex.schema.hasTable('Admini5trators')).to.be.true;
			expect(await knex.schema.hasTable('Auth0rLog')).to.be.true;
		} catch (err) {
			// Tables don't exist
			console.warn('Database is uninitialized or incomplete...');
			return false;
		}
		return true;
	}

	private static async createDatabase() {
		let knex = DBInitializer.knex;
		// void
		for (let tbl of Object.keys(db_schema)) {
			if(!(await knex.schema.hasTable(tbl))) {
				console.warn(`Table '${tbl}' not found...${String('').padEnd(20 - tbl.length)} => Creating`);
				await knex.schema.createTable(tbl, db_schema[tbl]);
			}
		}
	}
}

let db_schema = Indexed({
	Auth0rLog: (table: TableBuilder) => {
		table.increments('id');
		table.string('identifier');
		table.string('prod_error');
		table.string('dev_error');
		table.string('message');
		table.dateTime('date');
	},
	Users: (table: TableBuilder) => {
		table.increments('id');
		table.string('identifier');
		table.binary('password', 60);
		table.string('opaque', 32);
	},
	Admini5trators: (table: TableBuilder) => {
		table.integer('user_id');
		table.integer('permissor_id');
		table.unique(['user_id']);
		table.foreign('user_id').references('id').inTable('Users');
		table.foreign('permissor_id').references('id').inTable('Users');
	}
});
