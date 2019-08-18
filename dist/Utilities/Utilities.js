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
exports.log = (message, ...optionalParams) => setTimeout(() => console.log(message, ...optionalParams));
exports.warn = (message, ...optionalParams) => setTimeout(() => console.warn(message, ...optionalParams));
exports.error = (message, ...optionalParams) => setTimeout(() => console.error(message, ...optionalParams));
//# sourceMappingURL=Utilities.js.map