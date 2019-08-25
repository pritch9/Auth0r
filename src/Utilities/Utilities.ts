export function Timeout(promise: Promise<any>, timeout: number) {
	return Promise.race([
		promise,
		new Promise((resolve, reject) => {
			let id = setTimeout(() => {
				clearTimeout(id);
				reject(   `Promise timed out in ${timeout}ms`);
			}, timeout);
		})
	]);
}
