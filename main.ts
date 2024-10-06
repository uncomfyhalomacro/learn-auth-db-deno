import { Application, Router } from "jsr:@oak/oak";
import "jsr:@std/dotenv/load";
import register from "handler/register";
import login from "handler/login";
import vip from "handler/vip";

const router = new Router();

router.post("/register", register);

router.post("/login", login);

router.get("/vip", vip);

const app = new Application();

app.use(router.routes());
app.use(router.allowedMethods({
	throw: false,
}));

app.listen("127.0.0.1:5555");
