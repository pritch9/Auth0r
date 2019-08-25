export default class Config {
    [index: string]: any | undefined;
    defaults: any;
    name: string;
    constructor(options: any);
    private assertDefaults;
}
