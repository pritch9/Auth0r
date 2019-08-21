import { Request, RequestHandler, Response } from 'express';

export default async function(req: Request, res: Response, next) {
	if (req['user']) {

	} else {
		res.sendStatus(403);
	}
}
