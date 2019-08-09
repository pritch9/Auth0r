import {ENV, error, getEnv, log, warn} from "./Utilities/Utilities";
import * as jwt from "jsonwebtoken";
import {Auth0rRepo} from "../Repo/Auth0rRepo";
import path from "path";
import fs from "fs";
import jsjws from 'jsjws';
import crypto from 'crypto';
import deasync from 'deasync';

let verifySync = deasync(jwt.verify);

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

const authorizationRegex = new RegExp(/^Bearer: (.*):([0-9]*)$/);

export class Auth0r {
    private readonly public_key_file: string;
    private readonly private_key_file: string;
    protected readonly public_key: string;
    protected readonly private_key: string;
    private readonly issuer: string;
    private repo: Auth0rRepo;
    private readonly generateKeyPairSync;
    public get dbReady() { return this.repo.ready };

    constructor(options: Auth0rOptions) {
        this.generateKeyPairSync = deasync(this.generateKeyPair);
        if (!checkRSAKeys(options.public_key, options.private_key)) {
            // key file
            this.public_key_file = options.public_key;
            this.private_key_file = options.private_key;
            let { public_key, private_key } = this.generateKeyPairSync();
            this.public_key = public_key;
            this.private_key = private_key;
        } else {
            // key literal
            this.public_key = options.public_key;
            this.private_key = options.private_key;
        }

        this.issuer = options.issuer;
        this.repo = new Auth0rRepo({
            user_identifier: options.user_identifier || 'email',
            connection: options.connection
        });
    }

    public async middleware(req, res, next) {
        if (env === ENV.DEVELOPMENT) log('Auth0r reading request');
        if (req.headers && req.headers.authorization != undefined) {
            let groups = authorizationRegex.exec(req.headers.authorization);
            if (groups && groups.length == 3) {
                let token = groups[1];
                let user_id = +groups[2];
                if (isNaN(user_id)) {
                    res.sendStatus(401);
                    return;
                }
                let verified;
                try {
                    verified = await this.verifyToken(user_id, token, req)
                } catch (err) {
                    throw(err);
                }
                if (verified) {
                    // verified
                    delete req.user;
                    req.user = user_id;
                    next();
                } else {
                    // unverified
                    res.sendStatus(403);
                }
            } else {
                res.sendStatus(401);
            }
        } else {
            delete req.user;
            next();
        }
    }

    private signToken(user_id: number, o: string) {
        let signingOptions = {
            issuer: this.issuer,
            subject:  'user',
            audience:  String(user_id),
            expiresIn:  "12h",
            algorithm:  "RS256"
        };
        let payload = {
            o: o
        };
        return jwt.sign(payload, this.private_key, signingOptions);
    }
    public async verifyToken(user_id: number, token: string, request): Promise<boolean> {
        let verifyOptions = {
            issuer: this.issuer,
            subject:  'user',
            audience:  String(user_id),
            expiresIn:  "12h",
            algorithm:  "RS256"
        };
        let decoded;
        try {
            decoded = verifySync(token, this.public_key, verifyOptions);
        } catch (err) {
            if (env === ENV.DEVELOPMENT) {
                error("Unable to verify user: No opaque token given!");
            }
            return false;
        }
        if (decoded.o) {
            try {
                return await this.repo.verifyOpaque(user_id, decoded.o, request);
            } catch(err) {
                throw err;
            }
        } else {
            return false;
        }
    }

    public async tryLogin(user_id: string, password: string) {
        let attempt;
        try {
            attempt = await this.repo.login(user_id, password);
        } catch (err) {
            throw err;
        }
        return this.signToken(attempt.id, attempt.opaque);
    }
    public async tryRegister(user_id, password) {
        return this.repo.register(user_id, password);
    }

    public static generateOpaqueKey(): string {
        return crypto.randomBytes(24).toString('base64');
    }
    private async generateKeyPair(cb: (err, result) => void) {
        let pub: string, priv: string;
        let pubKeyFile = this.public_key || path.resolve(__dirname, '../rsa_keys/pubkey.pem');
        let privKeyFile = this.private_key || path.resolve(__dirname, '../rsa_keys/privkey.pem');
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
            let key = jsjws.generatePrivateKey(2048, 65537);
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

        cb(null, { public_key: pub, private_key: priv });
    }

    static compareKeyTwins(auth0rInstance: Auth0r, auth0rInstance2: Auth0r) {
        return Auth0r.compareKeys(auth0rInstance, auth0rInstance2.public_key, auth0rInstance2.private_key);
    }
    static compareKeys(auth0rInstance: Auth0r, public_key: string, private_key: string) {
        return auth0rInstance.public_key == public_key && auth0rInstance.private_key == private_key;
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
