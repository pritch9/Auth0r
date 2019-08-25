export default function Indexed(options: any) {
	return new IndexedObject(options);
}

export class IndexedObject {
	[index:string]: any | undefined;

	constructor(options: any) {
		Object.assign(this, options);
	}
}
