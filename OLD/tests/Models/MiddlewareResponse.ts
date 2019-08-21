export class MiddlewareResponse {
	public response: any;
	public sendStatus = this.send;

	public send(response) {
		this.response = response;
	}
}
