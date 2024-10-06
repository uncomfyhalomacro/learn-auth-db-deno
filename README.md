# Deno Auth DB Sample

This is example code on how you will use Deno for development with custom middleware + auth + JWT.

You must first generate a token by running the following command

```bash
deno task generateToken
```

Copy the values between the pair of backtick characters e.g. `` `VALUE` `` -> `VALUE`.

Then paste those values to a `.env` file. See `.env.example` file for where you should paste it as it will be obvious.

Lastly, run the following command to launch your backend

```bash
deno task serve
```

Here are the API routes you can experiment with `curl`:
- `http://127.0.0.1:5555/login`
- `http://127.0.0.1:5555/register`
- `http://127.0.0.1:5555/vip`
- `http://127.0.0.1:5555/hello`
- `http://127.0.0.1:5555/update`

Remember, `127.0.0.1` does not necessarily mean it's aliased to `localhost`.
