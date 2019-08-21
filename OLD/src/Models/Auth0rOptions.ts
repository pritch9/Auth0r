import {Express} from 'express';

export class Auth0rOptions {
	public issuer: string;
	public connection: any;
	public app: Express;
	public public_key?: string;
	public private_key?: string;
	public user_identifier?: string;
	public admin_panel?: boolean;
}
