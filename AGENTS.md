# leopard-doas

`doas` — minimal privilege elevation, OpenBSD doas style, ISC licensed.

- Installed setuid root (`04755`). The kernel applies `S_ISUID` in exec and
  switches the process to the owner's XUT identity (uid 0 → `XUT_Root`).
- No doas-specific elevation syscall. The only kernel primitive is
  `SXAH_CHECK_USER_PASSWORD`, which requires effective Root and does not
  change identity.
- Config: `/system/config/doas.conf` (fallback `/config/doas.conf`).
- `permit admin`, `permit user NAME`, `permit NAME`; no config means Admin-only.
- `-u root` is accepted; other targets are not implemented yet.
- Password prompt uses termios ECHO off; never log the password.
- Do not add sudo-compatible options or PAM semantics here.
