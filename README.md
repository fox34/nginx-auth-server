# nginx-auth-request-server

A **lightweight HTTP authentication backend** to be used with Nginx (`ngx_http_auth_request_module`) for authenticating website visitors against Linux system users via PAM with TOTP-based two-factor authentication.

## Request Flow

![Request flow diagram](docs/nginx-auth-request.svg)

---

## Project Scope and Goals

This project is designed to be a **simple and minimal authenticator** rather than a full-featured user/session manager.
It is intentionally kept simple and easy to understand for improved hackability.

> If you want to add new features, please open a *discussion* first before creating a PR.  
> For more extensive changes, feel free to fork it to suit your needs.

Since this is my very first rust project, code may be suboptimal to some extent - use at your own risk.
PRs to improve code quality and security are highly appreciated!

---

## Usage

```
Usage: nginx-auth-server [OPTIONS] --listen <LISTEN> --shadow-file <SHADOW_FILE>

Options:
      --listen <LISTEN>
          Listening address, e.g. 127.0.0.1:1337
      --shadow-file <SHADOW_FILE>
          Path of TOTP shadow file, e.g. /etc/shadow_totp
      --session-file <SESSION_FILE>
          Session persistence file, e.g. /tmp/nginx-auth-server.sessions
      --session-lifetime <SESSION_LIFETIME>
          Session lifetime. Valid: <number><m|h|d|y> (e.g. 30m, 2h, 7d, 1y) [default: 1y]
  -v, --verbose
          Enable verbose output
  -h, --help
          Print help
  -V, --version
          Print version
```

---

## Setup

### 1. Acquiring the binary

Use a precompiled binary from the [releases](https://github.com/YOUR_REPO/releases) section or build it yourself:

```bash
cargo build --release
```

You might need to install the following dependencies first:

```bash
sudo apt install libclang-dev build-essential libpam0g-dev libpam0g
```

### 2. Create the TOTP shadow file

- Example path: `/etc/shadow_totp` (customizable via `--shadow-file`)
- Format: `username,totp-secret` (Base32)
- You can generate TOTP secrets with any generator you want ([example web application](https://it-tools.tech/otp-generator))
- **Only users listed in this file are allowed to log in!**

Example:

```
alice,JBSWY3DPEHPK3PXP
bob,KZXW6YTBORSXEZJO
```

Set appropriate permissions:

```bash
sudo chown YOUR_SERVICE_USER /etc/shadow_totp
sudo chmod 600 /etc/shadow_totp
```

### 3. Set up as a systemd service

A sample unit file is available in the `examples` directory.

```bash
# Copy compiled binary to /usr/local/bin; change source path accordingly if you downloaded a precompiled binary
sudo cp target/release/nginx-auth-request-server /usr/local/bin/

# Modify unit file as needed
sudo cp examples/systemd.service /etc/systemd/system/

# Enable and start service
sudo systemctl enable --now nginx-auth-request-server
```

### 4. Configure nginx

- Provide a login form at `/var/www/auth` (A sample login form is available in the examples directory.)
- Adjust nginx config using snippets from `examples/etc/nginx`

Make sure to include request rate limiting (e.g. `limit_req_zone`) to mitigate brute-force attacks.

---

## Security Notes

- The binary has access to PAM: keep it secure.
- TOTP shadow file must be protected from unauthorized access.
- Brute-force protection is implemented **via nginx only** — consider checking or adding further safeguards if used in production.

## License

Licensed under **MIT**.

## Contributing

Bugfixes and code improvements are welcome.
For new features: please open a GitHub Discussion first to align scope and vision.
