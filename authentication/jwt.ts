import { decodeBase64 } from "@std/encoding";
import { create, verify } from "jsr:@zaubrik/djwt";
import User from "types/user";

const jwtSecret = decodeBase64(Deno.env.get("JWT_SECRET") ?? "");
const key = await crypto.subtle.importKey(
	"raw",
	jwtSecret,
	{ name: "HMAC", hash: "SHA-512" },
	true,
	["sign", "verify"],
);

const generateJwt = async (payload: User | undefined) => {
	if (!payload) return payload;

	const jwt = await create({
		alg: "HS512",
		type: "JWT",
	}, {
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
