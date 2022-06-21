import {expect} from 'chai';

export class MiddlewareNext {
	public ran: boolean;

	constructor() {
		this.ran = false;
	}

	public run(req, res) {
		this.ran = true;
		res.sendStatus(200);
		expect(req).to.not.be.undefined;
		expect(res).to.not.be.undefined;
	}
}
