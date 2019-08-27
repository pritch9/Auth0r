import { Application } from 'express';
import APIManager from './API/APIManager';
import DBInitializer from './API/Database/DBInitializer';
import Auth0rMiddleware from './Middleware/Auth0rMiddleware';
import Auth0rConfig, {Auth0rConfiguration} from './Models/Auth0rConfig';
export default class Auth0r {

	private static _instance: Auth0r;
	static get instance(): Auth0r {
		return Auth0r._instance;
	};

	private static database: any;
	private static app_name: string;
	private static email_identifier: boolean;

	private static storeOptions(options: Auth0rConfiguration) {
		Auth0r.database = options.database;
		Auth0r.app_name = options.app_name as string;
		Auth0r.email_identifier = options.email_identifier as boolean;
	}

	public static async initialize(app: Application, options?: any) {
		options = Auth0rConfig(options);
		this.storeOptions(options);
		app.use(Auth0rMiddleware); // non-blocking
		await DBInitializer.initializeDatabase(options.database);
		APIManager.initializeAPI(app, options);
	}
}

function welcome() {
	console.log('**************************************************************************************');
	console.log('**************************************************************************************');
	console.log('*****                                                                            *****');
	console.log('*****          /$$$$$$              /$$     /$$        /$$$$$$                   *****');
	console.log('*****         /$$__  $$            | $$    | $$       /$$$_  $$                  *****');
	console.log('*****        | $$  \\ $$ /$$   /$$ /$$$$$$  | $$$$$$$ | $$$$\\ $$  /$$$$$$         *****');
	console.log('*****        | $$$$$$$$| $$  | $$|_  $$_/  | $$__  $$| $$ $$ $$ /$$__  $$        *****');
	console.log('*****        | $$__  $$| $$  | $$  | $$    | $$  \\ $$| $$\\ $$$$| $$  \\\__/        *****');
	console.log('*****        | $$  | $$| $$  | $$  | $$ /$$| $$  | $$| $$ \\ $$$| $$              *****');
	console.log('*****        | $$  | $$|  $$$$$$/  |  $$$$/| $$  | $$|  $$$$$$/| $$              *****');
	console.log('*****        |__/  |__/ \\\______/    \\\___/  |__/  |__/ \\\______/ |__/              *****');
	console.log('*****                                                                            *****');
	console.log('**************************************************************************************');
	console.log('**************************************************************************************');
}
