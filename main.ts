import { Application, Router, Status } from "@oak/oak";
import "@std/dotenv/load";
import register from "middlewares/register";
import login from "middlewares/login";
import vip from "middlewares/vip";
import checkAuth from "authentication/checkAuth";
import updateAccount from "middlewares/auth/updateAccount";

const router = new Router();
const authRouter = new Router();

router.post("/register", register).post("/login", login)
	// This will be used for comparing with `/hello` which is an auth-checked route
	// The reason why is because we can check authentication status
	// to authenticated/authorised needed actions per route, hence, why
	// we have a separate `Router` instance called `authRouter`.
	.get("/vip", vip)
	.get("/hello", (ctx) => {
		ctx.response.body = "Hello world";
	});

authRouter.get("/auth/hello", (ctx) => {
	ctx.response.body = "Hello world";
}).put("/auth/update", updateAccount);

const app = new Application();

app.use(router.allowedMethods());
app.use(authRouter.allowedMethods());

// No auth routes
app.use(router.routes());

// Auth Routes
app.use(
	async (ctx, next) => {
		const pathname = decodeURIComponent(ctx.request.url.pathname);
		if (
			ctx.request.method === "GET" &&
			pathname === "/auth/hello"
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
	authRouter.routes(),
);

app.listen(
	Deno.env.get("USE_TLS")
		? {
			hostname: "127.0.0.1",
			port: 5555,
			secure: true,
			cert: Deno.readTextFileSync(
				new URL("./tls/localhost.crt", import.meta.url),
			),
			key: Deno.readTextFileSync(
				new URL("./tls/localhost.key", import.meta.url),
			),
		}
		: { hostname: "127.0.0.1", secure: false, port: 5555 },
);
