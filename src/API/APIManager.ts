import {Application} from 'express';
import {Auth0rConfiguration} from '../Models/Auth0rConfig';
import KeySet from '../Models/KeySet';
import Registrar from './Account/Registrar';
import AdminAuthenticator from './Admin/Auth/AdminAuthenticator';
import Authenticator from './Auth/Authenticator';
import {Controller} from './Controller';

export default class APIManager {
	private static initialized = false;
	private static controllers: Controller[];
	private static database: any;
	private static email_identifier: boolean;

	static initializeAPI(app: Application, options: Auth0rConfiguration) {
		APIManager.database = options.database;
		APIManager.email_identifier = options.email_identifier;
		if (APIManager.initialized) { throw new Error('API already initialized!'); }

		APIManager.controllers = [
			new Registrar(APIManager.database, APIManager.email_identifier),
			new AdminAuthenticator(),
			new Authenticator(APIManager.database, options.keys || new KeySet())
		];
		let controller: Controller;
		for (controller of APIManager.controllers) {
			controller.initializeRoutes(app);
			console.log(`[${controller.name}] initialized`);
		}
	}
}
