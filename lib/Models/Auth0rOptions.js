"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const Options_1 = __importDefault(require("./Options"));
class Auth0rConfig extends Options_1.default {
    constructor() {
        super(...arguments);
        this.name = 'Auth0rConfig';
        this.defaults = {
            database: {
                client: 'sqlite3',
                connection: './database/Auth0rDefault.db'
            },
            app_name: 'Auth0r'
        };
    }
}
exports.default = Auth0rConfig;
//# sourceMappingURL=Auth0rConfig.js.map
