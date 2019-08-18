declare module 'Auth0r' {
	export class Auth0r {
		constructor(options: Auth0rOptions);
		public middleware(req, res, next): Promise<any>;
		public verifyToken(user_id: number, token: string, request): Promise<boolean>;
		public tryLogin(user_id: string, password: string): Promise<any>;
		public tryRegister(user_id, password): Promise<string>;
	}

	export class Auth0rOptions {
		public issuer: string;
		public connection: any;
		public public_key?: string;
		public private_key?: string;
		public user_identifier?: string;
	}
}
