import type { RouterContext } from "@oak/oak/router";
import { encodeBase64 } from "@std/encoding";
import type User from "types/user";
import db from "database";
import { argon2Hasher } from "authentication/crypto";
interface RegisterBody {
	username?: string;
	passphrase?: string;
}

const register = async (
	ctx: RouterContext<
		"/register",
		Record<string | number, string | undefined>,
		// deno-lint-ignore no-explicit-any
		Record<string, any>
	>,
) => {
	const requestBody: RegisterBody | null = await ctx.request
		.body.json().catch((err) => {
			console.log(err);
			return null;
		});

	if (!requestBody) {
		ctx.response.status = 422;
		ctx.response.body = {
			message: "Empty input",
			status: 422,
		};

		return;
	}
	
	const { username, passphrase } = requestBody;

	if (!username?.trim() || !passphrase?.trim()) {
		ctx.response.status = 422;
		ctx.response.body = {
			message: "Username and passphrase field cannot be empty",
			status: 422,
		};

		return;
	}

	const stmt = db.prepare(`
		SELECT username FROM users WHERE username = '${username}';
	`);

	const row = stmt.get<User>();

	if (row === undefined) {
		const randSalt = crypto.getRandomValues(new Uint8Array(32));
		const salt = encodeBase64(randSalt);
		const hashedPassphrase = encodeBase64(argon2Hasher(passphrase, salt));
		const changes = db.exec(
			`INSERT INTO users(username, passphrase, salt) VALUES ('${username}', '${hashedPassphrase}', '${salt}')`,
		);
		console.log(changes);
		console.log(`
			username: ${username},
			passphrase: ${passphrase}`);
		// Handle it here
		ctx.response.body = {
			message: `User \`${username}\` is now registered`,
			status: 200,
		};

		return;
	}

	ctx.response.status = 409;
	ctx.response.body = {
		message: `User \`${username}\` already exists`,
		status: 409,
	};

	return;
};

export default register;
