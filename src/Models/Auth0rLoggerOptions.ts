import * as Knex from 'knex';

export class Auth0rLoggerOptions {
	public user_identifier: string;
	public knex: Knex;
}
