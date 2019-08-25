export default class Config {
	[index:string]: any | undefined;

	constructor(options: any, defaults: any = {}) {
		Object.assign(this, defaults, options);
	}
}
