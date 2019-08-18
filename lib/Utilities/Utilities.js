"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ENV;
(function (ENV) {
    ENV[ENV["DEVELOPMENT"] = 0] = "DEVELOPMENT";
    ENV[ENV["STAGING"] = 1] = "STAGING";
    ENV[ENV["PRODUCTION"] = 2] = "PRODUCTION";
})(ENV = exports.ENV || (exports.ENV = {}));
const envMap = {
    'development': ENV.DEVELOPMENT,
    'staging': ENV.STAGING,
    'production': ENV.PRODUCTION
};
function getEnv() {
    return envMap[process.env.NODE_ENV];
}
exports.getEnv = getEnv;
let env = getEnv();
let async = {
    log: (message, ...optionalParams) => setTimeout(() => console.log(message || '', ...optionalParams)),
    warn: (message, ...optionalParams) => setTimeout(() => console.warn(message || '', ...optionalParams)),
    error: (message, ...optionalParams) => setTimeout(() => console.error(message || '', ...optionalParams))
};
let sync = {
    log: console.log,
    warn: console.warn,
    error: console.error
};
exports.log = (env === ENV.DEVELOPMENT) ? sync.log : async.log;
exports.warn = (env === ENV.DEVELOPMENT) ? sync.warn : async.warn;
exports.error = (env === ENV.DEVELOPMENT) ? sync.error : async.error;
//# sourceMappingURL=Utilities.js.map