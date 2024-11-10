import { decodeBase64 } from "@std/encoding";
import { create, getNumericDate, verify } from "@zaubrik/djwt";
import type User from "types/user";

/** This will return a value of `UintArray` which
 I think Postman does not support since it wants the
 secret key (decoded form) to be purely string
**/
const jwtSecret = decodeBase64(Deno.env.get("JWT_SECRET") ?? "");

/**
 * Our JWT signature used.
 */
const key = await crypto.subtle.importKey(
	"raw",
	jwtSecret,
	{ name: "HMAC", hash: "SHA-512" },
	false,  // This does not need to be extractable. No need to store since we are using this signature client-side
	["sign", "verify"],
);

/**
 * Generates a Json Web Token (JWT) for user login authentication.
 * This JWT is used throughout a user's session until it expires.
 * @param payload User data such as username and id
 * @param origin domain name of source origin
 * @returns `Promise<string|undefined>`
 */
const generateJwt = async (payload: User | undefined, origin: string) => {
	if (!payload) return payload;

	/**
	 * **N**ot **B**e**F**ore
	 */
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

/**
 * Verifies the signature of the JWT
 * @param jwt The JWT signature
 * @returns `string` value as the username.
 */
const verifyJwt = async (jwt: string) => {
	const payload: { user: string } = await verify(
		jwt,
		key,
	);

	return payload;
};

export { generateJwt, verifyJwt };
