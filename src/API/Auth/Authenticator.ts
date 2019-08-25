import {compare} from 'bcrypt';
import {Application, NextFunction, Request, Response} from 'express';
import KeyBank from '../../KeyBank/KeyBank';
import KeySet from '../../Models/KeySet';
import {Logger} from '../../Utilities/Logger';
import {Controller} from '../Controller';
import Knex = require('knex');

let errors = {
	INVALID_CREDS: new Error('Invalid identifier or password'),
	SERVER_ERROR: new Error('Server Error (not you don\' worry'),
	BAD_ID: new Error('Malformed identifier'),
	FAILED_PASSWORD_ATTEMPT: new Error('User attempted password failed'),
};

export default class Authenticator implements Controller {
	name = 'Authenticator';

	private static keyBank: KeyBank;
	private static database: any;

	constructor(database: any, raw_keys: KeySet) {
		Authenticator.keyBank = new KeyBank(raw_keys);
		Authenticator.database = database;
	}

	initializeRoutes(app: Application) {
		app.post('/auth/login', Authenticator.LoginHandler);
	}

	static async verifyOpaque(user_id: number, token: string): Promise<boolean> {
		// TO-DO
		return false;
	}

	private static async LoginHandler(req: Request, res: Response, next: NextFunction) {
		let { identifier, password } = req.body;

		if (!identifier) {
			return next(errors.BAD_ID);
		}
		if (!password) {
			return next(errors.INVALID_CREDS);
		}

		let knex = Knex(Authenticator.database);

		let validUserFound = false;
		let userPassedAuth = false;
		let userTokenStored = false;

		try {
			let { password: hashed, id } = (await knex.table('Users')
				.select('password', 'id')
				.where('identifier', identifier))[0];

			validUserFound = true;

			userPassedAuth = await compare(password, hashed);

			if (!userPassedAuth) {
				Logger.logError(errors.FAILED_PASSWORD_ATTEMPT);
				return next(errors.INVALID_CREDS);
			}

			// user validated and ready for token
			let opaque = Authenticator.keyBank.generateOpaqueToken();

			await knex.table('Users')
				.update({ opaque })
				.where({ identifier });

			userTokenStored = true;

			let payload = {
				admin: await Authenticator.isAdmin(+id),
				id: +id
			};

			let token = await Authenticator.keyBank.sign(payload, identifier);

			res.send({ token, opaque });
		} catch (err) {
			if (!validUserFound) {
				// Logger.logError(errors.NO_VALID_USER_FOUND);
				return next(errors.INVALID_CREDS);
			}
			if (!userPassedAuth) {
				Logger.logError(errors.FAILED_PASSWORD_ATTEMPT);
				return next(errors.INVALID_CREDS);
			}
			if (userTokenStored) {
				try {
					await knex.table('Users')
						.update({ opaque: null })
						.where( { identifier });
				} catch (err) {
					Logger.logError(err);
				}
			}

			Logger.logError(err);
			return next(errors.SERVER_ERROR);
		}

	}

	public static async isAdmin(id: number) {
		let knex = Knex(Authenticator.database);
		try {
			let results = (await knex.table('Admini5trators')
				.select('user_id')
				.where({ user_id: id }));

			return results.length === 1 && results[0].user_id === id;
		} catch (err) {
			Logger.logError(err);
			return false;
		}
	}
}


