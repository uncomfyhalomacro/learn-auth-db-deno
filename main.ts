import { Application, Router } from "@oak/oak";
import "@std/dotenv/load";
import register from "middlewares/register";
import login from "middlewares/login";
import vip from "middlewares/vip";
import checkAuth from "authentication/checkAuth";
import updateAccount from "middlewares/auth/updateAccount";

const router = new Router();
const authRouter = new Router();
const controller = new AbortController();

router.post("/register", register).post("/login", login)
	// This will be used for comparing with `/hello` which is an auth-checked route
	// The reason why is because we can check authentication status
	// to authenticated/authorised needed actions per route, hence, why
	// we have a separate `Router` instance called `authRouter`.
	.get("/vip", vip)
	.get("/hello", (ctx) => {
		ctx.response.body = "Hello world";
	}).get("/close", (ctx) => {
		ctx.response.body = "Bye!";
		controller.abort("User has invoked to close the connection");
	});

authRouter.get(
	"/auth/hello",
	async (ctx, next) => {
		const pathname = decodeURIComponent(ctx.request.url.pathname);
		if (
			ctx.request.method === "GET" &&
			(pathname === "/auth/hello" ||
				pathname === "/auth/close")
		) {
			return await next();
		}

		if (
			ctx.request.method === "PUT" &&
			pathname === "/auth/update"
		) {
			return await next();
		}
		ctx.response.status = 404;
		ctx.response.body = {
			message: "Bad Request",
			status: 404,
		};
	},
	checkAuth,
	(ctx) => {
		ctx.response.body = "Hello world";
	},
).put("/auth/update", updateAccount).get("/auth/close", async (ctx) => {
	await ctx.request.body.stream?.cancel("Closing");
	ctx.response.body = "Bye!";
	controller.abort("User has invoked to close the connection");
});

const app = new Application();

app.use(router.allowedMethods());
app.use(authRouter.allowedMethods());

// No auth routes
app.use(router.routes());

// Auth Routes
app.use(
	authRouter.routes(),
);

const { signal } = controller;
app.listen(
	Deno.env.get("USE_TLS")
		? {
			hostname: "127.0.0.1",
			port: 5555,
			secure: true,
			cert: Deno.readTextFileSync(
				"./tls/localhost.crt",
			),
			key: Deno.readTextFileSync(
				"./tls/localhost.key",
			),
			signal,
		}
		: {
			hostname: "127.0.0.1",
			secure: false,
			port: 5555,
			signal,
		},
);
