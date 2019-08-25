"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const Auth0rConfig_1 = __importDefault(require("./Models/Auth0rConfig"));
class Auth0r {
    static initialize(app, options) {
        options = new Auth0rConfig_1.default(options);
        console.log('config: ' + JSON.stringify(options));
    }
}
exports.default = Auth0r;
//# sourceMappingURL=index.js.map
