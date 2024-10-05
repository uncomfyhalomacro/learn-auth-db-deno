import { Application, Router } from "jsr:@oak/oak";
import { Database } from "jsr:@db/sqlite";
import { crypto } from "jsr:@std/crypto";
import { decodeBase64, encodeBase64 } from "@std/encoding";
import { create, verify } from "jsr:@zaubrik/djwt";

import "jsr:@std/dotenv/load";

const TOKEN = decodeBase64(Deno.env.get("API_KEY") ?? "");
const SALT_TOKEN = decodeBase64(Deno.env.get("SALT_SECRET") ?? "");

const ALGO = {
	name: "AES-GCM",
	// also our nonce. it can only be used ONCE. So if server dies
	// then database dies.
	// FIXED: WORKAROUND IS TO USE `importKey`
	iv: TOKEN,
};

const SALT_ALGO = {
	name: "AES-GCM",
	// also our nonce. it can only be used ONCE. So if server dies
	// then database dies.
	// FIXED: WORKAROUND IS TO USE `importKey`
	iv: SALT_TOKEN,
};

const cryptoKey = await crypto.subtle.importKey(
	"raw",
	TOKEN,
	{
		name: "AES-GCM",
	},
	true,
	["encrypt", "decrypt"],
);

const saltCryptoKey = await crypto.subtle.importKey(
	"raw",
	SALT_TOKEN,
	{
		name: "AES-GCM",
	},
	true,
	["encrypt", "decrypt"],
);

const db = new Database("./database/users.db");

const create_table_command = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL,
		passphrase TEXT NOT NULL,
		salt TEXT NOT NULL
	)
`;

if (db.open) {
	db.exec(create_table_command);
} else {
	console.error("DB is not connected");
	Deno.exit(1);
}

const router = new Router();

interface User {
	id: number;
	username: string;
	passphrase: string;
	salt: string;
}

router.post("/register", async (ctx) => {
	const { username, passphrase }: { username: string; passphrase: string } =
		await ctx.request.body.json();
	if (!username.trim()) {
		ctx.response.status = 422;
		ctx.response.body = JSON.stringify({
			message: "Username field cannot be empty",
			status: 422,
		});

		return;
	}
	const stmt = db.prepare(`
		SELECT username FROM users WHERE username = '${username}';
	`);

	const row = stmt.get<User>();

	if (row === undefined) {
		const randSalt = crypto.getRandomValues(new Uint8Array(16));
		const enc = new TextEncoder();
		const salt = encodeBase64(randSalt);
		const saltPayload = enc.encode(salt);
		const passphrasePayload = enc.encode(passphrase.concat(salt));
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
			`INSERT INTO users(username, passphrase, salt) VALUES ('${username}', '${encryptedPassphrase}', '${encryptedSalt}')`,
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
});

router.post("/login", async (ctx) => {
	const { username, passphrase }: { username: string; passphrase: string } =
		await ctx.request.body.json();
	if (!username.trim()) {
		ctx.response.status = 422;
		ctx.response.body = JSON.stringify({
			message: "Username field cannot be empty",
			status: 422,
		});

		return;
	}

	if (!passphrase.trim()) {
		ctx.response.status = 422;
		ctx.response.body = JSON.stringify({
			message: "Passphrase field cannot be empty",
			status: 422,
		});

		return;
	}
	const stmt = db.prepare(`
		SELECT username, passphrase, salt FROM users WHERE username = '${username}';
	`);
	const user = stmt.get<User>();
	if (!user) {
		ctx.response.status = 400;
		ctx.response.body = JSON.stringify({
			message: "User does not exist",
			status: 400,
		});

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
		const jwtSecret = decodeBase64(Deno.env.get("JWT_SECRET") ?? "");

		const key = await crypto.subtle.importKey(
			"raw",
			jwtSecret,
			{ name: "HMAC", hash: "SHA-512" },
			true,
			["sign", "verify"],
		);

		const jwt = await create({
			alg: "HS512",
			type: "JWT",
		}, {
			user: user.username,
		}, key);

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
		ctx.response.body = JSON.stringify({
			message: `Correct credentials for \`${username}\``,
			status: 200,
		});

		return;
	}
});

router.get("/vip", async (ctx) => {
	const jwtFromCookie = await ctx.cookies.get("user");
	const authHeader = ctx.request.headers.get("Authorization");
	console.log(
		`Has Cookie: ${jwtFromCookie !== undefined}\nHas Auth Header: ${
			authHeader !== null
		}`,
	);
	console.log("Cookie", jwtFromCookie);
	const [, jwt] = authHeader ? authHeader.split(" ") : [null, null];

	if (!jwt || !jwtFromCookie) {
		ctx.response.status = 403;
		ctx.response.body = JSON.stringify({
			message: "You are forbidden!",
			status: 403,
		});
		return;
	}

	if (jwt === jwtFromCookie) {
		const jwtSecret = decodeBase64(Deno.env.get("JWT_SECRET") ?? "");

		const key = await crypto.subtle.importKey(
			"raw",
			jwtSecret,
			{ name: "HMAC", hash: "SHA-512" },
			true,
			["sign", "verify"],
		);

		const payload1: { user: string } = await verify(
			jwtFromCookie,
			key,
		);

		const payload2: { user: string } = await verify(
			jwt,
			key,
		);

		if (payload1.user == payload2.user) {
			ctx.response.status = 200;
			ctx.response.body = JSON.stringify({
				message: "Yes! You are a VIP!",
				status: 200,
			});
			return;
		}
	}

	ctx.response.status = 403;
	ctx.response.body = JSON.stringify({
		message: "You are forbidden!",
		status: 403,
	});
	return;
});

const app = new Application();

app.use(router.routes());
app.use(router.allowedMethods({
	throw: false,
}));

app.listen("127.0.0.1:5555");
