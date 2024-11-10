import { decodeBase64, encodeBase64 } from "@std/encoding";
import { type Argon2Params, hash } from "@denosaurs/argontwo";

const TOKEN = decodeBase64(Deno.env.get("API_KEY") ?? "");
const encoder = new TextEncoder();

export const argon2Verify = (passphrase: string, salt: string, originalHash: string): boolean => {
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

export const argon2Hasher = (passphrase: string, salt: string): ArrayBuffer => {
	const encodedPassphrase = encoder.encode(passphrase);
	const encodedSalt = encoder.encode(salt);
	const params: Argon2Params = {
		algorithm: "Argon2id",
		secret: TOKEN,
		version: 0x13
	};
	return hash(encodedPassphrase, encodedSalt, params);
}

