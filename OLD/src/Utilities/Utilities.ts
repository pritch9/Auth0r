export enum ENV {
    DEVELOPMENT,
    STAGING,
    PRODUCTION
}
const envMap = {
    'development': ENV.DEVELOPMENT,
    'staging': ENV.STAGING,
    'production': ENV.PRODUCTION
};
export function getEnv(): ENV {
    return envMap[process.env.NODE_ENV];
}
let env = getEnv();
let async = {
    log: (message?: string, ...optionalParams: any[]): number => setTimeout(() => console.log(message || '', ...optionalParams)),
    warn: (message?: string, ...optionalParams: any[]): number => setTimeout(() => console.warn(message || '', ...optionalParams)),
    error: (message?: string, ...optionalParams: any[]): number => setTimeout(() => console.error(message || '', ...optionalParams))
};
let sync = {
    log: console.log,
    warn: console.warn,
    error: console.error
};
export let log = (env === ENV.DEVELOPMENT) ? sync.log : async.log;
export let warn = (env === ENV.DEVELOPMENT) ? sync.warn : async.warn;
export let error = (env === ENV.DEVELOPMENT) ? sync.error : async.error;
