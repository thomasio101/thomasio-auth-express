import { Request, RequestHandler } from 'express';
import {
	IDatabaseInterface,
	ISession,
	SessionAuthenticator,
	UserAuthenticator,
	UserCreator,
} from 'thomasio-auth-js-common/lib/server';

export interface IRequestWithSession<T> extends Request {
	session: ISession<T>;
}

export function authMiddleware<T>(authenticator: SessionAuthenticator<T>): RequestHandler {
	return async (req, res, next) => {
		const { ['x-session-id']: id, ['x-session-token']: token } = req.headers;

		if (typeof id === 'string' && typeof token === 'string') {
			const session: ISession<T> = { id, token, identity: null };

			if (await authenticator(session)) {
				(req as IRequestWithSession<T>).session = session;
				next();
			} else {
				res.status(403).send('Error from thomasio-auth-express.\nInvalid session.');
			}
			// TODO: Add customizable errors.
		} else {
			res.status(403).send('Error from thomasio-auth-express.\nInvalid headers.');
		}
	};
}

export function loginHandler<T>(authenticator: UserAuthenticator<T>): RequestHandler {
	return async (req, res) => {
		const { username, password }: { username: any; password: any } = req.body;

		if (typeof username === 'string' && typeof password === 'string') {
			// TODO: Add post processing for sessions to, for example, remove internal data from the session's identity.
			res.json(await authenticator(username, password));
		} else {
			res.status(400).send('Error from thomasio-auth-express.\nInvalid body.');
		}
	};
}

export type UserDataValidator<U> = (userData: U) => Promise<boolean>;

export function registrationHandler<E, I, U>(
	userCreator: UserCreator<E, I, U>,
	userDataValidator: UserDataValidator<U>,
): RequestHandler {
	return async (req, res) => {
		const { username, password, userData }: { username: any; password: any; userData: any } = req.body;

		const userDataValidationPromise = userDataValidator(userData);

		if (typeof username === 'string' && typeof password === 'string' && (await userDataValidationPromise)) {
			res.json(await userCreator(username, password, userData));
		} else {
			res.status(400).send('Error from thomasio-auth-express.\nInvalid body.');
		}
	};
}
