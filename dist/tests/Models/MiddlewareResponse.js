"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class MiddlewareResponse {
    constructor() {
        this.sendStatus = this.send;
    }
    send(response) {
        this.response = response;
    }
}
exports.MiddlewareResponse = MiddlewareResponse;
//# sourceMappingURL=MiddlewareResponse.js.map