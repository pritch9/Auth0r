import {SignOptions, VerifyOptions} from 'jsonwebtoken';
import * as jwt from 'jsonwebtoken';
import crypto from 'crypto';
import KeySet from '../Models/KeySet';
import deasync = require('deasync');
let fs = require('fs').promises;
let jsjws = require('jsjws');

let generateKeyPairSync = deasync(generateKeyPairAsync);

let default_sigining_options: SignOptions = {
	algorithm: 'RS256',
	issuer: 'Auth0r',
	expiresIn: '24h'
};

export default class KeyBank {

	private readonly keys: KeySet;
	private readonly options: SignOptions;
	private readonly opaqueLength: number;

	constructor(rawKeys: KeySet, signOptions?: SignOptions, opaqueLength?: number) {
		this.options = Object.assign(default_sigining_options, signOptions);
		this.opaqueLength = opaqueLength || 32;

		if (!checkRSAKeys(rawKeys)) {
			// key file
			this.keys = generateKeyPairSync(rawKeys);
		} else {
			// key literal
			this.keys = rawKeys;
		}
	}

	async verify(encrypted: string): Promise<any> {
		return jwt.verify(encrypted, this.keys.public_key, this.getOptions() as VerifyOptions);
	}

	async sign(payload: any, identifier: string) {
		return jwt.sign(payload, this.keys.private_key, this.getOptions(identifier) as SignOptions);
	}

	private getOptions(identifier?: string): SignOptions | VerifyOptions {
		let options = {};
		Object.assign(options, this.options, { audience: identifier });

		return options;
	}

	public generateOpaqueToken() {
		return crypto.randomBytes(3 * this.opaqueLength / 4).toString('base64');
	}

}

async function generateKeyPairAsync(rawKeys: KeySet, cb: (err?: Error, result?: { public_key: string, private_key: string }) => void) {
	const { public_key: raw_public_key, private_key: raw_private_key } = rawKeys;
	let pub = '';
	let priv = '';
	const pubKeyFile = raw_public_key || './rsa_keys/pubkey.pem';
	const privKeyFile = raw_private_key || './rsa_keys/privkey.pem';
	let genNewKeys = true;

	try {
		await fs.access(pubKeyFile);
		await fs.access(privKeyFile);
		pub = (await fs.readFile(pubKeyFile)).toString('utf-8');
		priv = (await fs.readFile(privKeyFile)).toString('utf-8');

		if (checkRSAKeys({ public_key: pub, private_key: priv })) {
			genNewKeys = false;
		}
	} catch (err) { }
	if (genNewKeys) {
		console.warn(`KeyBank keys were not loaded from a file, generating new keys`);
		const key = jsjws.generatePrivateKey(2048, 65537);
		pub = key.toPublicPem();
		priv = key.toPrivatePem();

		try {
			await fs.mkdir('./rsa_keys');
			await fs.writeFile(pubKeyFile, pub);
			await fs.writeFile(privKeyFile, priv);
		} catch (err) {
			cb(new Error('Unable to initialize RSA Key pair!  Auth0r will not work correctly!'));
		}
	}

	cb(undefined, { public_key: pub, private_key: priv });
}
function checkRSAKeys(rawKeys: KeySet) {
	let { public_key, private_key } = rawKeys;
	try {
		crypto.createPublicKey(public_key);
		crypto.createPrivateKey(private_key);
		return true;
	} catch (err) {
		return false;
	}
}
