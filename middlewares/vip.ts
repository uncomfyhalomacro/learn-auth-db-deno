import type { RouterContext } from "@oak/oak/router";
import { verifyJwt } from "authentication/jwt";

const vip = async (
	ctx: RouterContext<
		"/vip",
		Record<string | number, string | undefined>,
		// deno-lint-ignore no-explicit-any
		Record<string, any>
	>,
) => {
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
		ctx.response.body = {
			message: "You are forbidden!",
			status: 403,
		};
		return;
	}

	if (jwt === jwtFromCookie) {
		const payload1 = await verifyJwt(
			jwtFromCookie,
		);

		const payload2 = await verifyJwt(
			jwt,
		);

		if (payload1.user == payload2.user) {
			ctx.response.status = 200;
			ctx.response.body = {
				message: "Yes! You are a VIP!",
				status: 200,
			};
			return;
		}
	}

	ctx.response.status = 403;
	ctx.response.body = JSON.stringify({
		message: "You are forbidden!",
		status: 403,
	});
	return;
};

export default vip;
