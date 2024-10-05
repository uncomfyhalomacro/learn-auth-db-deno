import { crypto } from "jsr:@std/crypto";
import { encodeBase64 } from "@std/encoding";

const token = crypto.getRandomValues(new Uint8Array(12));
console.log(`GENERATED API_KEY:\`${encodeBase64(token)}\``);
const JSONKEY = await crypto.subtle.generateKey(
	{ name: "HMAC", hash: "SHA-512" },
	true,
	["sign", "verify"],
);
const exportJSONKEY = await crypto.subtle.exportKey("raw", JSONKEY);
console.log(`GENERATED JWT_SECRET:\`${encodeBase64(exportJSONKEY)}\``);
