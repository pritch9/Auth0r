import {expect, should, assert} from "chai";
import { Auth0r } from "../src";
import { fail } from "assert";

describe('Auth0r Test Suite', function() {
	it('should pass when asking for middleware', function() {
		let auth0r = new Auth0r({
			issuer: 'test',
			public_key: '',
			private_key: ''
		});

		let middleware = auth0r.middleware;

		expect(middleware).to.exist;
	});

	it('should generate a random opaque key', function() {
		let hashMap = {};
		console.log("Example opaque key: %s", Auth0r.generateOpaqueKey());
		for (let x = 0; x < 10000; ++x) {
			let randomKey = Auth0r.generateOpaqueKey();
			if (randomKey.length !== 32) {
				fail(`Random opaque key length invalid!  (length: ${randomKey.length})`);
			}
			if (hashMap[randomKey]) {
				fail("Random Opaque key collision detected!");
			}
			hashMap[randomKey] = true;
		}
		expect(Object.keys(hashMap)).to.have.length(10000);
	});
});
