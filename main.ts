import { Application, Router } from "@oak/oak";
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
	.get("/vip", vip);

authRouter.get("/auth/hello", (ctx) => {
	ctx.response.body = "Hello world";
}).put("/auth/update", updateAccount);

const app = new Application();

// No auth routes
app.use(router.routes());

// Auth Routes
app.use(checkAuth, authRouter.routes());
app.use(
	router.allowedMethods({
		throw: false,
	}),
	authRouter.allowedMethods(),
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
