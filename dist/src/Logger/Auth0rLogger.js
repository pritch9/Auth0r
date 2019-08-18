"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Utilities_1 = require("../Utilities/Utilities");
const dev = Utilities_1.getEnv() === Utilities_1.ENV.DEVELOPMENT;
let knex; // protected static variable
class Auth0rLogger {
    constructor(options) {
        this.user_identifier = options.user_identifier;
    }
    logError(identifier, func, prodError, devError) {
        if (dev) {
            Utilities_1.error(`============ Error ============\n
                            \tIdentifier:\t${identifier}\n
                            \tFunction:\t${func}\n
                            \tProd Error:\t${prodError.name}\n
                            \tDev Error:\t${devError.name}\n
                            \tMessage:\t${devError.message}\n
                            ===============================`);
        }
        else {
            knex.table('Auth0r_Log')
                .insert({
                identifier,
                func,
                prod_error: prodError.name,
                dev_error: devError.name,
                message: devError.message,
            }).catch((err) => {
                Utilities_1.error(err);
            });
        }
    }
}
exports.Auth0rLogger = Auth0rLogger;
//# sourceMappingURL=Auth0rLogger.js.map