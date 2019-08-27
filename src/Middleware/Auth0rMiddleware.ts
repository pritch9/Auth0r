import {Request, Response, NextFunction} from 'express';
import Authenticator from '../API/Auth/Authenticator';
import {Logger} from '../Utilities/Logger';
import base64url from 'base64url';

export default function Auth0rMiddleware(req: Request, res: Response, next: NextFunction) {
	delete req.body.user;
	if (req.headers.authorization) {
		let token: string;
		try {
			token = req.headers.authorization.split('Bearer: ')[1];
		} catch (err) {
			return next(); // continue if failed
		}
		if (req.headers.opaque == undefined) {
			res.sendStatus(403);
		}
		Authenticator.verifyUser(token, String(req.headers.opaque)).then((valid) => {
			if (valid) {
				req.body.user = {
					id: JSON.parse(base64url.decode(token.split('.')[1])).id
				}
			}

			return next();
		}).catch(err => {
			Logger.logError(err);
			next();// continue anyways
		});
	} else {
		return next();
	}
}
