/*
	Usage


	Auth0r.initialize(app);

 */


import {Express, Request, Response} from 'express';

export default class Auth0r {

	public static initialize(app: Express) {
		app.post('/api', (req: Request, res: Response) => {
			let body = req.body;

			console.log(`${typeof body}`);
		});
	}

}
