import {Server} from '@overnightjs/core';
import crypto, {RsaPrivateKey, RsaPublicKey} from 'crypto';
import deasync from 'deasync';
import {Express} from 'express';
import fs from 'fs';
import jsjws from 'jsjws';
import * as jwt from 'jsonwebtoken';
import path from 'path';
import {AdminAuthController} from './Controllers/Admin/AuthController';
import middleware = require('./Middleware/Auth0rMiddleware');
import {Auth0rOptions} from './Models/Auth0rOptions';
import {Auth0rRepo} from './Repository/Auth0rRepo';
import {ENV, error, getEnv, log, warn} from './Utilities/Utilities';

const verifySync = deasync(jwt.verify);

const env = getEnv();
if (env === ENV.DEVELOPMENT) {
	warn('DEBUG mode enabled');
}

const authorizationRegex = new RegExp(/^Bearer: (.*):([0-9]*)$/);

export class Auth0r extends Server {
	public get dbReady() {
		return this.repo.ready;
	}

	public static generateOpaqueKey(): string {
		return crypto.randomBytes(24).toString('base64');
	}

	public static compareKeyTwins(auth0rInstance: Auth0r, auth0rInstance2: Auth0r) {
		return Auth0r.compareKeys(auth0rInstance, auth0rInstance2.public_key, auth0rInstance2.private_key);
	}

	public static compareKeys(auth0rInstance: Auth0r, public_key: RsaPublicKey, private_key: RsaPrivateKey) {
		return auth0rInstance.public_key.key === public_key.key && auth0rInstance.private_key.key === private_key.key;
	}
	protected readonly public_key: RsaPublicKey;
	protected readonly private_key: RsaPrivateKey;
	private readonly public_key_file: string;
	private readonly private_key_file: string;
	private readonly issuer: string;
	private readonly admin_panel: boolean;
	private repo: Auth0rRepo;
	private readonly generateKeyPairSync;

	constructor(options: Auth0rOptions) {
		super(undefined, options.app);
		this.generateKeyPairSync = deasync(this.generateKeyPair);
		if (!checkRSAKeys(options.public_key, options.private_key)) {
			// key file
			this.public_key_file = options.public_key;
			this.private_key_file = options.private_key;
			const {public_key, private_key} = this.generateKeyPairSync();
			this.public_key = public_key;
			this.private_key = private_key;
		} else {
			// key literal
			this.public_key = { key: options.public_key };
			this.private_key = { key: options.private_key };
		}

		this.issuer = options.issuer;
		this.repo = new Auth0rRepo({
			connection: options.connection,
			user_identifier: options.user_identifier || 'email',
		});
		super.addControllers(new AdminAuthController());

		// TO-DO: need a way to give user a way to create an account

		if (!!options.admin_panel) {
			this.app.get('admin', (request, response) => {
				const reqPath = request.path;

			});
		}
	}

	public async tryLogin(user_id: string, password: string) {
		const { id, o } = await this.repo.login(user_id, password);
		return this.signToken(id, o);
	}

	public async login(request, response, next) {
		const user_id = request.body.user_id;
		const password = request.body.password;
		let token;
		try {
			token = await this.tryLogin(user_id, password);
		} catch (err) {
			return next(err);
		}
		response.send(token);
	}

	public async tryRegister(user_id, password) {
		return this.repo.register(user_id, password);
	}

	public async register(request, response, next) {
		const user_id = request.body.user_id;
		const password = request.body.password;
		let attempt;
		try {
			attempt = await this.tryRegister(user_id, password);
		} catch (err) {
			return next(err);
		}
		response.send(attempt);
	}

	private signToken(user_id: number, o: string) {
		const signingOptions = {
			algorithm: 'RS256',
			audience: String(user_id),
			expiresIn: '12h',
			issuer: this.issuer,
			subject: 'user',
		};
		const payload = {
			o,
		};
		return jwt.sign(payload, this.private_key, signingOptions);
	}

	private async generateKeyPair(cb: (err, result) => void) {
		let pub: string;
		let priv: string;
		const pubKeyFile = this.public_key_file || path.resolve(__dirname, '../rsa_keys/pubkey.pem');
		const privKeyFile = this.private_key_file || path.resolve(__dirname, '../rsa_keys/privkey.pem');
		let genNewKeys = true;

		if (fs.existsSync(pubKeyFile) && fs.existsSync(privKeyFile)) {
			pub = fs.readFileSync(pubKeyFile).toString('utf-8');
			priv = fs.readFileSync(privKeyFile).toString('utf-8');

			if (checkRSAKeys(pub, priv)) {
				genNewKeys = false;
			} else {
				// Check rsa keys not good when loading already created private keys.
				error('Soo, your keys are no bueno.  We will generate new keys');
			}
		}
		if (genNewKeys) {
			const key = jsjws.generatePrivateKey(2048, 65537);
			pub = key.toPublicPem();
			priv = key.toPrivatePem();

			try {
				fs.mkdirSync(path.resolve(__dirname, '../rsa_keys'));
				fs.writeFileSync(pubKeyFile, pub);
				fs.writeFileSync(privKeyFile, priv);
			} catch (err) {
				error(err);
				cb(new Error('Unable to initialize RSA Key pair!  Auth0r will not work correctly!'), null);
			}
		}

		cb(null, {public_key: pub, private_key: priv});
	}
}

function checkRSAKeys(public_key: string, private_key: string) {
	try {
		crypto.createPublicKey(public_key);
		crypto.createPrivateKey(private_key);
		return true;
	} catch (err) {
		return false;
	}
}
