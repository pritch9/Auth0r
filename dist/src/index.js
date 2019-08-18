"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const deasync_1 = __importDefault(require("deasync"));
const fs_1 = __importDefault(require("fs"));
const jsjws_1 = __importDefault(require("jsjws"));
const jwt = __importStar(require("jsonwebtoken"));
const path_1 = __importDefault(require("path"));
const Auth0rRepo_1 = require("./Repository/Auth0rRepo");
const Utilities_1 = require("./Utilities/Utilities");
const verifySync = deasync_1.default(jwt.verify);
const env = Utilities_1.getEnv();
if (env === Utilities_1.ENV.DEVELOPMENT) {
    Utilities_1.warn('DEBUG mode enabled');
}
const authorizationRegex = new RegExp(/^Bearer: (.*):([0-9]*)$/);
class Auth0r {
    get dbReady() {
        return this.repo.ready;
    }
    static generateOpaqueKey() {
        return crypto_1.default.randomBytes(24).toString('base64');
    }
    static compareKeyTwins(auth0rInstance, auth0rInstance2) {
        return Auth0r.compareKeys(auth0rInstance, auth0rInstance2.public_key, auth0rInstance2.private_key);
    }
    static compareKeys(auth0rInstance, public_key, private_key) {
        return auth0rInstance.public_key === public_key && auth0rInstance.private_key === private_key;
    }
    constructor(options) {
        this.generateKeyPairSync = deasync_1.default(this.generateKeyPair);
        if (!checkRSAKeys(options.public_key, options.private_key)) {
            // key file
            this.public_key_file = options.public_key;
            this.private_key_file = options.private_key;
            const { public_key, private_key } = this.generateKeyPairSync();
            this.public_key = public_key;
            this.private_key = private_key;
        }
        else {
            // key literal
            this.public_key = options.public_key;
            this.private_key = options.private_key;
        }
        this.issuer = options.issuer;
        this.repo = new Auth0rRepo_1.Auth0rRepo({
            connection: options.connection,
            user_identifier: options.user_identifier || 'email',
        });
    }
    middleware(req, res, next) {
        return __awaiter(this, void 0, void 0, function* () {
            if (env === Utilities_1.ENV.DEVELOPMENT) {
                Utilities_1.log('Auth0r reading request');
            }
            if (req.headers && req.headers.authorization != undefined) {
                const groups = authorizationRegex.exec(req.headers.authorization);
                if (groups && groups.length === 3) {
                    const token = groups[1];
                    const user_id = +groups[2];
                    if (isNaN(user_id)) {
                        res.sendStatus(401);
                        return;
                    }
                    let verified;
                    try {
                        verified = yield this.verifyToken(user_id, token, req);
                    }
                    catch (err) {
                        throw (err);
                    }
                    if (verified) {
                        // verified
                        delete req.user;
                        req.user = user_id;
                        next();
                    }
                    else {
                        // unverified
                        res.sendStatus(403);
                    }
                }
                else {
                    res.sendStatus(401);
                }
            }
            else {
                delete req.user;
                next();
            }
        });
    }
    verifyToken(user_id, token, request) {
        return __awaiter(this, void 0, void 0, function* () {
            const verifyOptions = {
                algorithm: 'RS256',
                audience: String(user_id),
                expiresIn: '12h',
                issuer: this.issuer,
                subject: 'user',
            };
            let decoded;
            try {
                decoded = verifySync(token, this.public_key, verifyOptions);
            }
            catch (err) {
                if (env === Utilities_1.ENV.DEVELOPMENT) {
                    Utilities_1.error('Unable to verify user: No opaque token given!');
                }
                return false;
            }
            if (decoded.o) {
                try {
                    return yield this.repo.verifyOpaque(user_id, decoded.o, request);
                }
                catch (err) {
                    throw err;
                }
            }
            else {
                return false;
            }
        });
    }
    tryLogin(user_id, password) {
        return __awaiter(this, void 0, void 0, function* () {
            let attempt;
            try {
                attempt = yield this.repo.login(user_id, password);
            }
            catch (err) {
                throw err;
            }
            return this.signToken(attempt.id, attempt.opaque);
        });
    }
    tryRegister(user_id, password) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.repo.register(user_id, password);
        });
    }
    signToken(user_id, o) {
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
    generateKeyPair(cb) {
        return __awaiter(this, void 0, void 0, function* () {
            let pub;
            let priv;
            const pubKeyFile = this.public_key || path_1.default.resolve(__dirname, '../rsa_keys/pubkey.pem');
            const privKeyFile = this.private_key || path_1.default.resolve(__dirname, '../rsa_keys/privkey.pem');
            let genNewKeys = true;
            if (fs_1.default.existsSync(pubKeyFile) && fs_1.default.existsSync(privKeyFile)) {
                pub = fs_1.default.readFileSync(pubKeyFile).toString('utf-8');
                priv = fs_1.default.readFileSync(privKeyFile).toString('utf-8');
                if (checkRSAKeys(pub, priv)) {
                    genNewKeys = false;
                }
                else {
                    // Check rsa keys not good when loading already created private keys.
                    Utilities_1.error('Soo, your keys are no bueno.  We will generate new keys');
                }
            }
            if (genNewKeys) {
                const key = jsjws_1.default.generatePrivateKey(2048, 65537);
                pub = key.toPublicPem();
                priv = key.toPrivatePem();
                try {
                    fs_1.default.mkdirSync(path_1.default.resolve(__dirname, '../rsa_keys'));
                    fs_1.default.writeFileSync(pubKeyFile, pub);
                    fs_1.default.writeFileSync(privKeyFile, priv);
                }
                catch (err) {
                    Utilities_1.error(err);
                    cb(new Error('Unable to initialize RSA Key pair!  Auth0r will not work correctly!'), null);
                }
            }
            cb(null, { public_key: pub, private_key: priv });
        });
    }
}
exports.Auth0r = Auth0r;
function checkRSAKeys(public_key, private_key) {
    try {
        crypto_1.default.createPublicKey(public_key);
        crypto_1.default.createPrivateKey(private_key);
        return true;
    }
    catch (err) {
        return false;
    }
}
//# sourceMappingURL=index.js.map