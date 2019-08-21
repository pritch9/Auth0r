import {Middleware} from '@overnightjs/core';
import {RsaPublicKey} from 'crypto';
import deasync = require('deasync');
import {NextFunction, Request, RequestHandler, Response} from 'express';
import jwt = require('jsonwebtoken');
import {Auth0r} from '../index';
import {Auth0rRepo} from '../Repository/Auth0rRepo';
import {ENV, error, getEnv, log} from '../Utilities/Utilities';

const env = getEnv();
const authorizationRegex = new RegExp(/^Bearer: (.*):([0-9]*)$/);
const verifySync = deasync(jwt.verify);

export default (issuer: string, public_key: RsaPublicKey, repo: Auth0rRepo) =>
	(req: Request, res: Response, next: NextFunction): RequestHandler => async () => {
		if (env === ENV.DEVELOPMENT) {
			log('Auth0r reading request');
		}
		if (req.headers && req.headers.authorization != undefined) {
			const groups = authorizationRegex.exec(req.headers.authorization);
			if (groups && groups.length === 3) {
				const token = groups[1];
				const user_id = +groups[2];
				if (isNaN(user_id)) {
					res.sendStatus(401);
					return;
				}
				let verified;
				try {
					verified = await this.verifyToken(user_id, token, req);
				} catch (err) {
					next(err);
				}
				if (verified) {
					// verified
					delete req['user'];
					req['user'] = user_id;
					next();
				} else {
					// unverified
					res.sendStatus(403);
				}
			} else {
				res.sendStatus(401);
			}
		} else {
			delete req['user'];
			next();
		}
	};

async function verifyToken(user_id: number, token: string, request): Promise<boolean> {
	const verifyOptions = {
		algorithm: 'RS256',
		audience: String(user_id),
		expiresIn: '12h',
		issuer: this.issuer,
		subject: 'user',
	};
	let decoded;
	try {
		decoded = verifySync(token, this.public_key, verifyOptions);
	} catch (err) {
		if (env === ENV.DEVELOPMENT) {
			error('Unable to verify user: No opaque token given!');
		}
		return false;
	}
	if (decoded.o) {
		try {
			return await this.repo.verifyOpaque(user_id, decoded.o, request);
		} catch (err) {
			throw err;
		}
	} else {
		return false;
	}
}
