import {Application} from 'express';

export interface Controller {

	name: string;
	initializeRoutes(app: Application): void;

}
