"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
class MiddlewareNext {
    constructor() {
        this.ran = false;
    }
    run(req, res) {
        this.ran = true;
        chai_1.expect(req).to.not.be.undefined;
        chai_1.expect(res).to.not.be.undefined;
    }
}
exports.MiddlewareNext = MiddlewareNext;
//# sourceMappingURL=MiddlewareNext.js.map