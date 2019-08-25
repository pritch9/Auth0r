"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Config {
    constructor(options) {
        this.defaults = {};
        this.name = 'Config';
        for (let key of Object.keys(this.defaults)) {
            if (this.hasOwnProperty(key)) {
                this[key] = options[key];
            }
            else {
                throw new Error(`Unknown property '${key}' on ${this.name}!`);
            }
        }
        this.assertDefaults();
    }
    assertDefaults() {
        let key;
        for (key of Object.keys(this.defaults)) {
            this[key] = this[key] || this.defaults[key];
        }
    }
}
exports.default = Config;
//# sourceMappingURL=Options.js.map