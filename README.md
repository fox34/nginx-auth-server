# nginx auth request server

This is a small http server, used to authenticate users via PAM and an auxiliary totp file for use with `ngx_http_auth_request_module`.

## Scope and code quality

Everything is *intentionally* kept as simple as possible, and as such, there is no comfortable user management or even a logout functionality.

This code is provided as-is without support.
Since this is my first rust project, the code quality may vary and be suboptimal to some extent.
Feel free to open a PR to improve potential issues. :-)

**Warning:** Use at your own risk, since error-handling is very, very basic.

## Recommended usage

Modify to your needs:

1. Compile using `cargo build --production` and place the binary in `/usr/local/bin`.
2. Add and enable systemd service. A sample for the unit file is in the `examples` directory.
3. Add TOTP secrets comma-separated as `username,secret` in `/etc/shadow_totp`. An example is provided in the `examples` directory. **Note:** Only users present in this file are allowed to log in.
4. Change ownership of `/etc/shadow_totp` to `root:shadow` and set permissions to 0640. Add service user (default `www-data`; recommended to change to dedicated user) to group `shadow`.
5. Add login form to `/var/www/auth`.
6. Add/modify nginx config as shown in `examples/nginx`.
