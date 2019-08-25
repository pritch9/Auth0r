import {Config, ConnectionConfig} from 'knex';
import Options from './Config';
import KeySet from './KeySet';

const defaults = {
	database: {
		client: 'sqlite3',
		connection: './database/Auth0rDefault.db'
	},
	app_name: 'Auth0r',
	email_identifer: true
};
// const name = 'Auth0rConfig';

export default function Auth0rConfig(options: any = {}) { return new Auth0rConfiguration(options); }
export class Auth0rConfiguration extends Options {
	database: any | undefined;
	app_name: string | undefined;
	email_identifer: boolean | undefined;
	keys: KeySet | undefined;

	constructor(options: any) {
		super(options, defaults);
	}
}
