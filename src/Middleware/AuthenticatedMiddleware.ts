import {Request, Response, NextFunction} from 'express';
import {Logger} from '../Utilities/Logger';

export default function ValidateUser(req: Request, res: Response, next: NextFunction) {
	try {
		if (req.body.user != undefined) {
			return next();
		}
	} catch (err) {
		Logger.logError(err);
	}
	res.sendStatus(403);
}
