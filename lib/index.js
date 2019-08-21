"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Auth0r {
    static initialize(app) {
        app.post('/api', (req, res) => {
            let body = req.body;
            console.log(`${typeof body}`);
        });
    }
}
exports.default = Auth0r;
//# sourceMappingURL=index.js.map