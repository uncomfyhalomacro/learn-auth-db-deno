import type { RouterContext } from "@oak/oak/router";
import { decodeBase64 } from "@std/encoding/base64";
import {
	ALGO,
	cryptoKey,
	SALT_ALGO,
	saltCryptoKey,
} from "authentication/crypto";
import { generateJwt } from "authentication/jwt";
import db from "database";
import type User from "types/user";

const login = async (
	ctx: RouterContext<
		"/login",
		Record<string | number, string | undefined>,
		// deno-lint-ignore no-explicit-any
		Record<string, any>
	>,
) => {
	const { username, passphrase }: {
		username: string;
		passphrase: string;
	} = await ctx.request.body.json();
	if (!username.trim()) {
		ctx.response.status = 422;
		ctx.response.body = {
			message: "Username field cannot be empty",
			status: 422,
		};

		return;
	}

	if (!passphrase.trim()) {
		ctx.response.status = 422;
		ctx.response.body = {
			message: "Passphrase field cannot be empty",
			status: 422,
		};

		return;
	}
	const stmt = db.prepare(`
		SELECT username, passphrase, salt FROM users WHERE username = '${username}';
	`);
	const user = stmt.get<User>();
	if (!user) {
		ctx.response.status = 400;
		ctx.response.body = {
			message: "User does not exist",
			status: 400,
		};

		return;
	}

	const dec = new TextDecoder();
	const decodedEncryptedPassphrase = decodeBase64(user.passphrase);
	const decodedEncryptedSalt = decodeBase64(user.salt);
	const decryptPassphrase = await crypto.subtle.decrypt(
		ALGO,
		cryptoKey,
		decodedEncryptedPassphrase,
	);

	const decryptSalt = await crypto.subtle.decrypt(
		SALT_ALGO,
		saltCryptoKey,
		decodedEncryptedSalt,
	);

	const decryptPassphraseString = dec.decode(decryptPassphrase);
	const salt = dec.decode(decryptSalt);
	const saltedPassphrase = passphrase.concat(salt);

	if (decryptPassphraseString === saltedPassphrase) {
		const jwt = await generateJwt(user, ctx.request.url.origin);

		if (!jwt) {
			ctx.response.status = 403;
			ctx.response.body = {
				message:
					"User did not exist. Failed to generate JWT. Please file a bug report.",
				status: 403,
			};
			return;
		}

		const expiryDate = new Date();
		expiryDate.setDate(expiryDate.getDate() + 365);

		ctx.cookies.set("user", jwt, {
			httpOnly: true,
			secure: false,
			signed: false,
			sameSite: "lax",
			expires: expiryDate,
			path: "/",
		});

		ctx.response.status = 200;
		ctx.response.body = {
			message: `Correct credentials for \`${username}\``,
			status: 200,
		};

		return;
	}
};

export default login;
