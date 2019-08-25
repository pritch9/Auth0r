import {Request, Response, Application, NextFunction} from 'express';
import {Logger} from '../../Utilities/Logger';
import {Controller} from '../Controller';
import Knex = require('knex');
import {hash} from 'bcrypt';

const email_validator = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

export default class Registrar implements Controller {
	name = 'Registrar';
	private static email_identifer: boolean;
	private static database: any;

	constructor(database: any, email_identifer: boolean) {
		Registrar.email_identifer = email_identifer;
		Registrar.database = database;
	}

	initializeRoutes(app: Application) {
		app.post('/account/register', Registrar.RegistrationHandler);
	}

	private static async RegistrationHandler(req: Request, res: Response, next: NextFunction) {
		let knex = Knex(Registrar.database);
		let { identifier, password } = req.body;

		if (!identifier) {
			return next(new Error('Identifier must be provided!'));
		}
		if (!password) {
			return next(new Error('Password must be provided!'));
		}

		if (Registrar.email_identifer) {
			if(!identifier.match(email_validator)) {
				return next(new Error('Malformed Email Address!'));
			}
		}
		let hashed: string;
		try {
			hashed = await hash(password, 12);
			await knex.table('Users').insert({ identifier, password: hashed });
			res.send(identifier);
		} catch (err) {
			Logger.logError(err);
			return next(new Error('Server Error'));
		}
	};

}
