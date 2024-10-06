import { verifyJwt } from "authentication/jwt";
import type { Context, Next } from "jsr:@oak/oak";

const checkAuth = async (
	ctx: Context,
	next: Next,
) => {
	if (
		!decodeURIComponent(ctx.request.url.pathname).endsWith("/hello") ||
		!decodeURIComponent(ctx.request.url.pathname).endsWith("/update")
	) return await next();

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
			message: "Missing credentials. Not authenticated.",
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
				message: "Authenticated",
				status: 200,
			};
			return await next();
		}
	}

	ctx.response.status = 403;
	ctx.response.body = JSON.stringify({
		message: "Not authenticated",
		status: 403,
	});
	return;
};

export default checkAuth;
