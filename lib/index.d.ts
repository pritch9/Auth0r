import {Auth0rOptions} from './Models/Auth0rOptions';

export declare class Auth0r {

	public static generateOpaqueKey(): string;

	public static compareKeyTwins(auth0rInstance: Auth0r, auth0rInstance2: Auth0r): boolean;

	public static compareKeys(auth0rInstance: Auth0r, public_key: string, private_key: string): boolean;
	public readonly dbReady: boolean;

	protected readonly public_key: string;
	protected readonly private_key: string;
	private readonly public_key_file;
	private readonly private_key_file;
	private readonly issuer;
	private repo;
	private readonly generateKeyPairSync;

	private signToken;
	private generateKeyPair;

	constructor(options: Auth0rOptions);

	public middleware(req: any, res: any, next: any): Promise<void>;

	public verifyToken(user_id: number, token: string, request: any): Promise<boolean>;

	public tryLogin(user_id: string, password: string): Promise<any>;

	public tryRegister(user_id: any, password: any): Promise<string>;
}
