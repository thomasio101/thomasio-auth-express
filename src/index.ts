import { Request, RequestHandler } from 'express';

export interface ISession<T> {
	readonly id: string;
	readonly token: string;
	identity: T | null;
}

export interface IRequestWithSession<T> extends Request {
	session: ISession<T>;
}

export type Authenticator<T> = (session: ISession<T>) => boolean;

export function authMiddleware<T>(authenticator: Authenticator<T>): RequestHandler {
	return (req, res, next) => {
		const { ['x-session-id']: id, ['x-session-token']: token } = req.headers;

		if (typeof id === 'string' && typeof token === 'string') {
			const session: ISession<T> = { id, token, identity: null };

			if (authenticator(session)) {
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
