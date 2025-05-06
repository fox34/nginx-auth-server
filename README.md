# nginx auth request server

This is a **small and lightweight** http authentication server, to be used by nginx with `ngx_http_auth_request_module` to authenticate your website visitors against linux system users via PAM, providing additional security with two-factor-authentication.

## Request flow

![Request flow diagram](docs/nginx-auth-request.svg)

## Scope and code quality

### Project goals

Everything is *intentionally* kept as simple and minimal as viable.
This project is more a simple to understand tech-demo and minimal working example rather than a full-featured user and session manager.
If you really do want to add features, please open a *discussion* first before you create a PR.
Otherwise, feel free to create a fork for your personal requirements.

Since this is my very first rust project, code may be suboptimal or even insecure to some extent - use at your own risk.
PRs to improve code quality and security are highly appreciated.

## Recommended usage

Modify to your needs:

1. Compile using `cargo build --production` or download a precompiled binary from the release section and place the binary in `/usr/local/bin`. Note: You probably need to install `libclang-dev build-essential libpam0g-dev libpam0g` for the required `pam`-crate to compile.
2. Add and enable systemd service. A sample for the unit file is in the `examples` directory.
3. Add TOTP secrets comma-separated as `username,secret` in the shadow file you specified in the unit file (`--shadow-file`, defaults to `/etc/shadow_totp`).  An example is provided in the `examples` directory. **Only users present in this file are allowed to log in.**
4. Set file permissions of this shadow file accordingly (readable by your selected service user, preferrably not readable by any other users or groups).
5. Add login form to `/var/www/auth`.
6. Include/add/modify nginx snippets and config as shown in `examples/etc/nginx`.
