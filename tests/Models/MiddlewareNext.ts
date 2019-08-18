import {expect} from 'chai';

export class MiddlewareNext {
	public ran: boolean;

	constructor() {
		this.ran = false;
	}

	public run(req, res) {
		this.ran = true;
		expect(req).to.not.be.undefined;
		expect(res).to.not.be.undefined;
	}
}
