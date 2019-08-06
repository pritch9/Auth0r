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

export let log = (message?: string, ...optionalParams: any[]): number => setTimeout(() => console.log(message, ...optionalParams));
export let warn = (message?: string, ...optionalParams: any[]): number => setTimeout(() => console.warn(message, ...optionalParams));
export let error = (message?: string, ...optionalParams: any[]): number => setTimeout(() => console.error(message, ...optionalParams));
