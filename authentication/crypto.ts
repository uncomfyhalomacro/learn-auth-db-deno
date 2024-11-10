import { crypto } from "@std/crypto";
import { decodeBase64, encodeBase64 } from "@std/encoding";
import { type Argon2Params, hash } from "@denosaurs/argontwo";

const TOKEN = decodeBase64(Deno.env.get("API_KEY") ?? "");
const SALT_TOKEN = decodeBase64(Deno.env.get("SALT_SECRET") ?? "");

const encoder = new TextEncoder();

export const argon2Verify = (passphrase: string, salt: string, originalHash: string) => {
	const encodedPassphrase = encoder.encode(passphrase);
	const encodedSalt = encoder.encode(salt);
	const params: Argon2Params = {
		algorithm: "Argon2id",
		secret: TOKEN,
		version: 0x13
	};
	const ret = encodeBase64(hash(encodedPassphrase, encodedSalt, params)) === originalHash;
	return ret;
};

export const argon2Hasher = (passphrase: string, salt: string) => {
	const encodedPassphrase = encoder.encode(passphrase);
	const encodedSalt = encoder.encode(salt);
	const params: Argon2Params = {
		algorithm: "Argon2id",
		secret: TOKEN,
		version: 0x13
	};
	return hash(encodedPassphrase, encodedSalt, params);
}

export const ALGO = {
	name: "AES-GCM",
	// also our nonce. it can only be used ONCE. So if server dies
	// then database dies.
	// FIXED: WORKAROUND IS TO USE `importKey`
	iv: TOKEN,
};

export const SALT_ALGO = {
	name: "AES-GCM",
	// also our nonce. it can only be used ONCE. So if server dies
	// then database dies.
	// FIXED: WORKAROUND IS TO USE `importKey`
	iv: SALT_TOKEN,
};

export const cryptoKey = await crypto.subtle.importKey(
	"raw",
	TOKEN,
	{
		name: "AES-GCM",
	},
	true,
	["encrypt", "decrypt"],
);

export const saltCryptoKey = await crypto.subtle.importKey(
	"raw",
	SALT_TOKEN,
	{
		name: "AES-GCM",
	},
	true,
	["encrypt", "decrypt"],
);
