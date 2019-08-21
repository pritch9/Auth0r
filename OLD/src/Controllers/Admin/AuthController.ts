import { Controller, Delete, Get, Middleware, Post, Put } from '@overnightjs/core';
import {Express, Request, RequestHandler, Response} from 'express';
import Auth0rAdminMiddleware from '../../Middleware/Auth0rAdminMiddleware';
import Auth0rMiddleware from '../../Middleware/Auth0rMiddleware';

export default (m: RequestHandler) => new AdminAuthController(m);

@Controller('admin/')
class AdminAuthController {

	private middleware: RequestHandler;

	constructor(middleware) {
		this.middleware = middleware;
	}

	@Post('auth')
	public login(req: Request, res: Response) {

	}

	@Post('api/statistics/users/registers')
	@Middleware(this.middleware);
	@Middleware(Auth0rAdminMiddleware)
	public getNumberOfRegisteredUsers() {

	}
}
