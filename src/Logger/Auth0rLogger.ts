import Knex from 'knex';
import {Auth0rLoggerOptions} from '../Models/Auth0rLoggerOptions';
import {ENV, error, getEnv} from '../Utilities/Utilities';
import {Auth0rRepo} from "../Repository/Auth0rRepo";

const dev = getEnv() === ENV.DEVELOPMENT;

export class Auth0rLogger {
	private user_identifier: string;

	constructor(options: Auth0rLoggerOptions) {
		this.user_identifier = options.user_identifier;
	}

	public logError(identifier: string, func: string, prodError: Error, devError: Error) {
		if (dev) {
			error(`============ Error ============\n
                            \tIdentifier:\t${identifier}\n
                            \tFunction:\t${func}\n
                            \tProd Error:\t${prodError.name}\n
                            \tDev Error:\t${devError.name}\n
                            \tMessage:\t${devError.message}\n
                            ===============================`);
		} else {
			Auth0rRepo.knex.table('Auth0r_Log')
				.insert({
					identifier,
					func,
					prod_error: prodError.name,
					dev_error: devError.name,
					message: devError.message,
				}).catch((err) => {
				error(err);
			});
		}
	}
}
