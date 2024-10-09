import { verifyJwt } from "authentication/jwt";
import type { Context, Next } from "@oak/oak";

const checkAuth = async (
	ctx: Context,
	next: Next,
) => {
	const pathname = decodeURIComponent(ctx.request.url.pathname);
	if (!pathname.startsWith("/auth")) {
		ctx.response.status = 404;
		ctx.response.body = {
			message: "Bad Request",
			status: 404,
		};
		return;
	}

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
		}
	} else {
		ctx.response.status = 403;
		ctx.response.body = JSON.stringify({
			message: "Not authenticated",
			status: 403,
		});
		return;
	}

	return await next();
};

export default checkAuth;
