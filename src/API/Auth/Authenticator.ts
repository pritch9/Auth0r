import {compare} from 'bcrypt';
import {Application, NextFunction, Request, Response} from 'express';
import KeyBank from '../../KeyBank/KeyBank';
import ValidateUser from '../../Middleware/AuthenticatedMiddleware';
import KeySet from '../../Models/KeySet';
import {Logger} from '../../Utilities/Logger';
import {Controller} from '../Controller';
import Knex = require('knex');
import base64url from 'base64url';

let errors = {
	INVALID_CREDS: new Error('Invalid identifier or password'),
	SERVER_ERROR: new Error('Server Error (not you don\' worry'),
	BAD_ID: new Error('Malformed identifier'),
	FAILED_PASSWORD_ATTEMPT: new Error('User attempted password failed'),
};

let keyBank: KeyBank;
let databaseConfig: any;

export default class Authenticator implements Controller {
	name = 'Authenticator';

	constructor(database: any, raw_keys: KeySet) {
		keyBank = new KeyBank(raw_keys);
		databaseConfig = database;
	}

	initializeRoutes(app: Application) {
		app.post('/auth/login', Authenticator.LoginHandler);
		app.post('/auth/logout', ValidateUser, Authenticator.LogOutHandler);
	}

	private static async LogOutHandler(req: Request, res: Response, next: NextFunction) {
		try {
			let user_id = req.body.user.id;
			let knex = Knex(databaseConfig);

			await knex.table('Users').update({ opaque: knex.raw('NULL') }).where('id', user_id);
			res.sendStatus(200);
		} catch (err) {
			Logger.logError(err);
			return next(new Error('Internal Server Error'));
		}
	}

	private static async LoginHandler(req: Request, res: Response, next: NextFunction) {
		let {identifier, password} = req.body;

		if (!identifier) {
			return next(errors.BAD_ID);
		}
		if (!password) {
			return next(errors.INVALID_CREDS);
		}

		let knex = Knex(databaseConfig);

		let validUserFound = false;
		let userPassedAuth = false;
		let userTokenStored = false;

		try {
			let {password: hashed, id} = (await knex.table('Users')
				.select('password', 'id')
				.where('identifier', identifier))[0];

			validUserFound = true;

			userPassedAuth = await compare(password, hashed);

			if (!userPassedAuth) {
				Logger.logError(errors.FAILED_PASSWORD_ATTEMPT);
				return next(errors.INVALID_CREDS);
			}

			// user validated and ready for token
			let opaque = keyBank.generateOpaqueToken();

			await knex.table('Users')
				.update({opaque})
				.where({identifier});

			userTokenStored = true;

			let payload = {
				admin: await Authenticator.isAdmin(+id),
				id: +id
			};

			let token = await keyBank.sign(payload, identifier);

			res.send({token, opaque});
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
						.update({opaque: null})
						.where({identifier});
				} catch (err) {
					Logger.logError(err);
				}
			}

			Logger.logError(err);
			return next(errors.SERVER_ERROR);
		}

	}

	public static async verifyUser(token: string, opaque: string) {
		let spl = token.split('.');
		try {
			if (spl.length === 3) {
				let { id } = await keyBank.verify(token); // error handled, I think
				return await verifyOpaque(id, opaque);
			}
		} catch(err) {
			Logger.logError(err);
		}
		return false;
	}

	public static async isAdmin(id: number) {
		let knex = Knex(databaseConfig);
		try {
			let results = (await knex.table('Admini5trators')
				.select('user_id')
				.where({user_id: id}));

			return results.length === 1 && results[0].user_id === id;
		} catch (err) {
			Logger.logError(err);
			return false;
		}
	}
}

async function verifyOpaque(user_id: number, token: string): Promise<boolean> {
	if (user_id != undefined && token != undefined) {
		let knex = Knex(databaseConfig);
		try {
			let dbOpaque = (await knex.table('Users')
				.select('opaque')
				.where({id: user_id}))[0].opaque;

			return token === dbOpaque;
		} catch (err) {
			Logger.logError(err);
			return false;
		}
	}
	return false;
}

async function logOut(user_id: number): Promise<void> {
	if (user_id > 0) {
		let knex = Knex(databaseConfig);

		await knex.table('Users')
			.update({opaque: undefined})
			.where({id: user_id});
	}
	throw new Error(`Illegal argument 'user_id' received: ${String(user_id)}`);
}

async function reloadOpaque(user_id: number): Promise<string> {
	if (user_id > 0) {
		let newOpaque = keyBank.generateOpaqueToken();
		let knex = Knex(databaseConfig);

		try {
			await knex.table('Users')
				.update({opaque: newOpaque})
				.where({id: user_id});
			return newOpaque;
		} catch (err) {
			throw err;
		}
	}
	throw new Error(`Illegal argument 'user_id' received: ${String(user_id)}`);
}
