# leopard-doas

`doas` — minimal privilege elevation, OpenBSD doas style, ISC licensed.

- Installed setuid root (`04755`). The kernel applies `S_ISUID` in exec and
  switches the process to the owner's XUT identity (uid 0 → `XUT_Root`).
- No doas-specific elevation syscall. The only kernel primitive is
  `SXAH_CHECK_USER_PASSWORD`, which requires effective Root and does not
  change identity.
- Config: `/system/config/doas.conf` (fallback `/config/doas.conf`).
- Config must be owned by uid 0 and not group/world writable
  (`mode & 022 == 0`). Verify with `fstat()` on the open descriptor; reject
  with `doas: insecure config file` and deny everything otherwise. Missing
  config keeps the Admin-only default.
- `permit admin`, `permit user NAME`, `permit NAME`; no config means Admin-only.
- `-u root` is accepted; other targets are not implemented yet.
- Never pass the caller's `envp` to `execve()`. Build a fixed, bounded
  environment: keep only `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`,
  `LC_COLLATE`, `LC_NUMERIC`, `LC_TIME`, `COLORTERM`; force
  `PATH=/apps/system:/apps/leopard:/apps/builtin:/system/leopard`,
  `USER=root`, `LOGNAME=root`, `HOME=/`. Drop `LD_*`, `IFS`, `ENV`,
  `BASH_ENV`, `SHELL`, `PWD`, `OLDPWD`, and everything else.
- Search for commands only in the fixed safe directories, never the caller's
  `PATH`.
- Password prompt uses termios ECHO off; never log the password.
- Do not add sudo-compatible options or PAM semantics here.
