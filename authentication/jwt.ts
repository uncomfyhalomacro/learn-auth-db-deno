import { decodeBase64 } from "@std/encoding";
import { create, getNumericDate, verify } from "@zaubrik/djwt";
import type User from "types/user";

// This will return a value of `UintArray` which
// I think Postman does not support since it wants the
// secret key (decoded form) to be purely string
const jwtSecret = decodeBase64(Deno.env.get("JWT_SECRET") ?? "");
const key = await crypto.subtle.importKey(
	"raw",
	jwtSecret,
	{ name: "HMAC", hash: "SHA-512" },
	true,
	["sign", "verify"],
);

const generateJwt = async (payload: User | undefined, origin: string) => {
	if (!payload) return payload;

	const nbf = getNumericDate(60 * 60);

	const jwt = await create({
		alg: "HS512",
		type: "JWT",
	}, {
		exp: nbf,
		aud: origin,
		user: payload.username,
	}, key);

	return jwt;
};

const verifyJwt = async (jwt: string) => {
	const payload: { user: string } = await verify(
		jwt,
		key,
	);

	return payload;
};

export { generateJwt, verifyJwt };
