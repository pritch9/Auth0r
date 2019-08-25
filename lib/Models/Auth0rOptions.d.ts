import { Config } from 'knex';
import Options from './Options';
export default class Auth0rConfig extends Options {
    name: string;
    defaults: {
        database: {
            client: string;
            connection: string;
        };
        app_name: string;
    };
    database?: Config;
    app_name?: string;
}
