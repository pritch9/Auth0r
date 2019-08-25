import {Application, Response, Request} from 'express';
import {Controller} from '../../Controller';

export default class AdminAuthenticator implements Controller {
	name = 'AdminAuthenticator';

	initializeRoutes(app: Application): void {
		app.post('/admin/auth/login', AdminLoginHandler);
	}
}

function AdminLoginHandler(req: Request, res: Response) {
	console.log("AdminLoginHandler");
	res.sendStatus(400)
}
