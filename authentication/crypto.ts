import { crypto } from "jsr:@std/crypto";
import { decodeBase64 } from "jsr:@std/encoding";

const TOKEN = decodeBase64(Deno.env.get("API_KEY") ?? "");
const SALT_TOKEN = decodeBase64(Deno.env.get("SALT_SECRET") ?? "");

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
