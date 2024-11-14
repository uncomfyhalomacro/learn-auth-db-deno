import type { RouterContext } from "@oak/oak/router";
import { encodeBase64 } from "@std/encoding";
import type User from "types/user";
import db from "database";
import { argon2Hasher, argon2Verify } from "authentication/crypto";

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

	if (!oldUsername || !newUsername) {
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

	if (userExists) {
		ctx.response.status = 409;
		ctx.response.body = {
			message: `Username \`${newUsername}\` already taken`,
			status: 409,
		};
		return;
	}

	let usernameChangeMessage = "";
	let passphraseChangeMessage = "";
	const newPassphraseWithOldSalt = argon2Verify(
		passphrase ?? "",
		user.salt,
		user.passphrase,
	);
	if (newUsername === oldUsername) {
		usernameChangeMessage += "Username unchanged";
	} else {
		usernameChangeMessage +=
			`Username changed from \`${oldUsername}\` to \`${newUsername}\``;
	}

	if (!passphrase?.trim() || newPassphraseWithOldSalt) {
		passphraseChangeMessage += "Passphrase unchanged";
	} else {
		passphraseChangeMessage += "Passphrase changed";
	}

	if (
		(newUsername === oldUsername) &&
		newPassphraseWithOldSalt
	) {
		ctx.response.status = 304;
		ctx.response.body = {
			message:
				`No changes were being sent. ${usernameChangeMessage}. ${passphraseChangeMessage}`,
			status: 304,
		};
		return;
	}

	const randSalt = crypto.getRandomValues(new Uint8Array(32));
	const newSalt = encodeBase64(randSalt);
	const hashedPassphrase = encodeBase64(
		argon2Hasher(passphrase ?? "", newSalt),
	);
	const changes = db.exec(
		`
			UPDATE users 
			SET username = '${newUsername}', 
				passphrase = '${hashedPassphrase}',
				salt = '${newSalt}'
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
};

export default updateAccount;
