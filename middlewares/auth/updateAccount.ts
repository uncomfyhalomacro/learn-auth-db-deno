import type { RouterContext } from "@oak/oak/router";
import { decodeBase64, encodeBase64 } from "@std/encoding";
import type User from "types/user";
import {
	ALGO,
	cryptoKey,
	SALT_ALGO,
	saltCryptoKey,
} from "authentication/crypto";
import db from "database";
import checkAuth from "authentication/checkAuth";

interface UpdateRequestBody {
	username?: string;
	newUsername?: string;
	passphrase?: string;
}

const updateAccount = async (
	ctx: RouterContext<
		"/auth/update",
		Record<string | number, string | undefined>,
		// deno-lint-ignore no-explicit-any
		Record<string, any>
	>,
) => {
	const requestBody: UpdateRequestBody | null = await ctx.request
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

	const { username: oldUsername, newUsername, passphrase }: {
		username?: string;
		newUsername?: string;
		passphrase?: string;
	} = requestBody;

	if (!oldUsername || !newUsername || !passphrase) {
		ctx.response.status = 422;
		ctx.response.body = {
			message: "Username or passphrase field cannot be empty",
			status: 422,
		};

		return;
	}

	const stmt = db.prepare(`
		SELECT username, passphrase, salt FROM users WHERE username = '${newUsername}';
	`);

	const stmtUpdate = db.prepare(`
		SELECT username, passphrase, salt FROM users WHERE username = '${oldUsername}';
	`);

	const userExists = stmt.get<User>() !== undefined;
	const user = stmtUpdate.get<User>();

	if (!user) {
		ctx.response.status = 503;
		ctx.response.body = {
			message: `Not able to retrieve \`${oldUsername}\``,
			status: 503,
		};

		return;
	}

	if (!userExists) {
		let usernameChangeMessage = "";
		let passphraseChangeMessage = "";
		const randSalt = crypto.getRandomValues(new Uint8Array(16));
		const enc = new TextEncoder();
		const dec = new TextDecoder();
		const decodedEncryptedPassphrase = decodeBase64(
			user.passphrase,
		);
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

		if (newUsername === oldUsername) {
			usernameChangeMessage += "Username unchanged";
		} else {
			usernameChangeMessage +=
				`Username changed from \`${oldUsername}\` to \`${newUsername}\``;
		}

		if (decryptPassphraseString === saltedPassphrase) {
			passphraseChangeMessage += "Passphrase unchanged";
		} else {
			passphraseChangeMessage += "Passphrase changed";
		}

		if (
			(newUsername === oldUsername) &&
			(decryptPassphraseString === saltedPassphrase)
		) {
			ctx.response.status = 304;
			ctx.response.body = {
				message:
					`No changes were being sent. ${usernameChangeMessage}. ${passphraseChangeMessage}`,
				status: 304,
			};
			return;
		}

		const newSalt = encodeBase64(randSalt);
		const saltPayload = enc.encode(newSalt);
		const passphrasePayload = enc.encode(
			passphrase.concat(newSalt),
		);
		const encryptPassphrase = await crypto.subtle.encrypt(
			ALGO,
			cryptoKey,
			passphrasePayload,
		);
		const encryptSalt = await crypto.subtle.encrypt(
			SALT_ALGO,
			saltCryptoKey,
			saltPayload,
		);

		const encryptedPassphrase = encodeBase64(encryptPassphrase);
		const encryptedSalt = encodeBase64(encryptSalt);
		const changes = db.exec(
			`
			UPDATE users 
			SET username = '${newUsername}', 
				passphrase = '${encryptedPassphrase}',
				salt = '${encryptedSalt}'
			WHERE
				username = '${oldUsername}'
			`,
		);
		console.log(changes);
		console.log(`
			username: ${newUsername},
			passphrase: ${passphrase}`);
		// Handle it here
		ctx.response.body = {
			message: `${usernameChangeMessage}. ${passphraseChangeMessage}`,
			status: 200,
		};

		return;
	}

	ctx.response.status = 409;
	ctx.response.body = {
		message: `Username \`${newUsername}\` already taken`,
		status: 409,
	};

	return;
};

export default updateAccount;
