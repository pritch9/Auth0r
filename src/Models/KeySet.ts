export default class KeySet {
	public_key: string;
	private_key: string;

	constructor(public_key?: string, private_key?: string) {
		this.public_key = public_key || '';
		this.private_key = private_key || '';
	}
}
