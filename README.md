# xmip-core-authenticate-password

Authenticate by password: verifies a username and password against the capability's store of salted PBKDF2-HMAC-SHA256 verifiers. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

`PasswordAuthenticator::admits(user, secret)` is the gate's own verdict on the `password` claim a login makes, and what a server that logs a client in is handed as its check (`net::login::Check`): Xmip's SSH and FTP servers link no authenticator, since identity presentation is not a transport's (`architecture.toml`), and the Playground's far ends prove a password through it (open problem 59).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
