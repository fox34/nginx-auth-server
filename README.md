# nginx auth request server

This is a **small and lightweight** http server, to be used by nginx to authenticate users against linux system users via PAM and an auxiliary totp file with `ngx_http_auth_request_module`.

## Scope and code quality

### Project goals

Everything is *intentionally* kept as simple and minimal as viable.
This project is more a simple to understand tech-demo and minimal working example rather than a full-featured user and session manager.

This code is provided as-is without support.
Since this is my first rust project, the code quality may vary and be suboptimal to some extent.
Feel free to open a PR to improve potential issues. :-)

Use at your own risk, error handling is very, very basic.

### Planned features

- Session expiration
- Logout functionality

## Recommended usage

Modify to your needs:

1. Compile using `cargo build --production` and place the resulting binary in `/usr/local/bin`.
2. Add and enable systemd service. A sample for the unit file is in the `examples` directory.
3. Add TOTP secrets comma-separated as `username,secret` in the shadow file you specified in the unit file (`--shadow-file`, defaults to `/etc/shadow_totp`).  An example is provided in the `examples` directory. **Only users present in this file are allowed to log in.**
4. Set file permissions of this shadow file accordingly (readable by your selected service user, preferrably not readable by any other users or groups).
5. Add login form to `/var/www/auth`.
6. Add/modify nginx config as shown in `examples/nginx`.
