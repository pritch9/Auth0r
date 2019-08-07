import {ENV, error, getEnv, log, warn} from "./Utilities/Utilities";
import * as jwt from "jsonwebtoken";
import {Auth0rRepo} from "../Repo/Auth0rRepo";
import path from "path";
import fs from "fs";
import jsjws from 'jsjws';
import crypto from 'crypto';
import deasync from 'deasync';

const env = getEnv();
if (env === ENV.DEVELOPMENT) {
    warn('DEBUG mode enabled');
}

export class Auth0rOptions {
    issuer: string;
    connection: any;
    public_key?: string;
    private_key?: string;
    user_identifier?: string
}

/**
 * TODO:
 *  -   Sign new tokens when a user signs in
 *  -   Verify token when user makes a request
 */

export class Auth0r {
    private readonly public_key: string;
    private readonly private_key: string;
    private readonly issuer: string;
    private repo: Auth0rRepo;
    private generateKeyPairSync;

    constructor(options: Auth0rOptions) {
        this.public_key = options.public_key;
        this.private_key = options.private_key;
        this.generateKeyPairSync = deasync(Auth0r.generateKeyPair);
        if (!checkRSAKeys(this.public_key, this.private_key)) {
            error('Soo, your keys are no bueno.  We will generate new keys');
            let { pub, priv } = this.generateKeyPairSync();
            this.public_key = pub;
            this.private_key = priv;
        }

        this.issuer = options.issuer;
        this.repo = new Auth0rRepo({
            user_identifier: options.user_identifier || 'email',
            connection: options.connection
        });
    }

    middleware(req, res, next) {
        if (env === ENV.DEVELOPMENT) log('Auth0r reading request');
        if (req.headers.authorization) { // TODO: IDK WTF THIS IS -\_(.>.)_/-
            let token_user = req.headers.authorization.split('Bearer: ')[1].split(':');
            let token = token_user[0];
            let user_id = token_user[1];
            this.verifyToken(user_id, token, req).then((result) => {
                if (result) {
                    // verified
                    delete req.user;
                    req.user = user_id;
                    next();
                } else {
                    // unverified
                    res.sendStatus(403);
                }
            });
        }
    }

    private signToken(user_id: string, o: string) {
        let signingOptions = {
            issuer: this.issuer,
            subject:  'user',
            audience:  user_id,
            expiresIn:  "12h",
            algorithm:  "RS256"
        };
        let payload = {
            o: o
        };
        return jwt.sign(payload, this.private_key, signingOptions);
    }
    private verifyToken(user_id: string, token: string, request): Promise<boolean> {
        let verifyOptions = {
            issuer: this.issuer,
            subject:  'user',
            audience:  user_id,
            expiresIn:  "12h",
            algorithm:  "RS256"
        };
        return new Promise<boolean>((resolve, reject) => {
            jwt.verify(token, this.public_key, verifyOptions, (err, decoded) => {
                if (err) {
                    if (env === ENV.DEVELOPMENT) {
                        error("Unable to verify user: No opaque token given!");
                    }
                    resolve(false);
                } else {
                    if (decoded.o) {
                        this.repo.verifyOpaque(user_id, decoded.o, request).then((result) => {
                           resolve(result);
                        }).catch((err) => reject(err));
                    } else {
                        resolve(false);
                    }
                }
            });
        });

    }

    public get dbReady() { return this.repo.ready };

    private tryLogin(user_id: string, password: string) {
        return this.repo.login(user_id, password);
    }

    private tryRegister(user_id, password) {
        return this.repo.register(user_id, password);
    }

    public static generateOpaqueKey(): string {
        return crypto.randomBytes(24).toString('base64');
    }

    private static async generateKeyPair(cb: (err, result) => void) {
        let public_key: string, private_key: string;

        let pubKeyFile = path.resolve(__dirname, '../rsa_keys/pubkey.pem');
        let privKeyFile = path.resolve(__dirname, '../rsa_keys/privkey.pem');
        let genNewKeys = true;

        if (fs.existsSync(pubKeyFile) && fs.existsSync(privKeyFile)) {
            public_key = fs.readFileSync(pubKeyFile).toString('utf-8');
            private_key = fs.readFileSync(privKeyFile).toString('utf-8');

            if (checkRSAKeys(public_key, private_key)) {
                genNewKeys = false;
            } else {
                // Check rsa keys not good when loading already created private keys.
                error('Soo, your keys are no bueno.  We will generate new keys');
            }
        }
        if (genNewKeys) {
            let key = jsjws.generatePrivateKey(2048, 65537);
            public_key = key.toPublicPem();
            private_key = key.toPrivatePem();

            try {
                fs.mkdirSync(path.resolve(__dirname, '../rsa_keys'));
                fs.writeFileSync(pubKeyFile, public_key);
                fs.writeFileSync(privKeyFile, private_key);
            } catch (err) {
                error(err);
                cb(new Error('Unable to initialize RSA Key pair!  Auth0r will not work correctly!'), null);
            }
        }

        cb(null, { public_key, private_key });
    }

}

function checkRSAKeys(public_key: string, private_key: string) {
    try {
        crypto.createPublicKey(public_key);
        crypto.createPrivateKey(private_key);
        return true;
    } catch(err) {
        return false;
    }
}
