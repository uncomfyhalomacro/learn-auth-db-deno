import { crypto } from "@std/crypto";
import { encodeBase64 } from "@std/encoding";

const apiKey = crypto.getRandomValues(new Uint8Array(16));
console.log(`GENERATED API_KEY:\`${encodeBase64(apiKey)}\``);
// const JSONKEY = await crypto.subtle.generateKey(
// 	{ name: "HMAC", hash: "SHA-512" },
// 	true,
// 	["sign", "verify"],
// );
// const exportJSONKEY = await crypto.subtle.exportKey("raw", JSONKEY);
// console.log(`GENERATED JWT_SECRET:\`${encodeBase64(exportJSONKEY)}\``);
