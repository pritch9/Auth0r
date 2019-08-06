import {ENV, error, getEnv, log, warn} from "./Utilities/Utilities";
import * as jwt from "jsonwebtoken";
import {Auth0rRepo} from "../Repo/Auth0rRepo";

const crypto = require("crypto");

const env = getEnv();
if (env === ENV.DEVELOPMENT) {
    warn('DEBUG mode enabled');
}

export class Auth0rOptions {
    issuer: string;
    public_key: string;
    private_key: string;
    connection: any;
    user_identifier? = 'email'
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

    constructor(options: Auth0rOptions) {
        this.public_key = options.public_key;
        this.private_key = options.private_key;
        this.issuer = options.issuer;
        this.repo = new Auth0rRepo(options.connection);
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

    private tryLogin(user_id: string, password: string) {
        return this.repo.login(user_id, password);
    }

    private tryRegister(user_id, password) {
        return this.repo.register(user_id, password);
    }

    public static generateOpaqueKey(): string {
        return crypto.randomBytes(24).toString('base64');
    }

}
