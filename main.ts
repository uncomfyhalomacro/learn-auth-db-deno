import { Application, Router } from "jsr:@oak/oak";
import { Database } from "jsr:@db/sqlite";
import { crypto } from "jsr:@std/crypto";
import { decodeBase64, encodeBase64 } from "@std/encoding";
import { create, verify } from "jsr:@zaubrik/djwt";

import "jsr:@std/dotenv/load";

const TOKEN = decodeBase64(Deno.env.get("API_KEY") ?? "");
const ALGO = {
	name: "AES-GCM",
	// also our nonce ?
	iv: TOKEN,
};

const cryptoKey = await crypto.subtle.generateKey(
	{
		name: "AES-GCM",
		length: 256,
	},
	true,
	["encrypt", "decrypt"],
);

const db = new Database(new URL("./database/users.db", import.meta.url), {
	create: true,
});

const create_table_command = `
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY,
		username TEXT,
		passphrase TEXT
	)
`;

db.exec(create_table_command);

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
		const enc = new TextEncoder();
		const passphrasePayload = enc.encode(passphrase);
		const encryptPassphrase = await crypto.subtle.encrypt(
			ALGO,
			cryptoKey,
			passphrasePayload,
		);
		const encryptedPassphrase = encodeBase64(encryptPassphrase);
		const changes = db.exec(
			`INSERT INTO users(username, passphrase) VALUES ('${username}', '${encryptedPassphrase}')`,
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
		SELECT username, passphrase FROM users WHERE username = '${username}';
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
	const decryptPassphrase = await crypto.subtle.decrypt(
		ALGO,
		cryptoKey,
		decodedEncryptedPassphrase,
	);

	const decryptPassphraseString = dec.decode(decryptPassphrase);

	if (decryptPassphraseString === passphrase) {
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
app.use(router.allowedMethods());

app.listen("127.0.0.1:5555");
