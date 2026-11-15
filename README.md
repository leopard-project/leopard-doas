# leopard-doas

Minimal privilege elevation, inspired by OpenBSD `doas`. Binary: `doas`.

- `doas [-u root] command [args...]`
- Installed as `04755 root:root`; the kernel applies `S_ISUID` on exec and the
  process starts with the Root XUT identity.
- The caller still authenticates with their own account password through the
  root-only `SXAH_CHECK_USER_PASSWORD` syscall.
- Config decides *who* may use doas; the password decides *this invocation*.
- Root never needs a password.

Config (installed to `/system/config/doas.conf`):

```text
permit admin
permit user alice
```

If the file is absent, only Admin users are permitted.

The config is security-sensitive. It must be owned by uid 0 and must not be
group- or world-writable (`mode & 022 == 0`). Ownership and mode are checked
with `fstat()` on the descriptor that is actually read, so the path cannot be
swapped between check and read. A config that fails the check — or that cannot
be opened at all — is a hard error:

```text
doas: insecure config file
```

In that case every request is denied; there is no fallback to the Admin-only
default or to `/config/doas.conf`.

The calling environment is never passed to the target command. `doas` builds
a fixed, bounded environment from the whitelist:

- from the caller: `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`,
  `LC_COLLATE`, `LC_NUMERIC`, `LC_TIME`, `COLORTERM`
- fixed values: `PATH=/apps/system:/apps/leopard:/apps/builtin:/system/leopard`,
  `USER=root`, `LOGNAME=root`, `HOME=/`

Everything else is dropped, including `LD_*`, `IFS`, `ENV`, `BASH_ENV`,
`SHELL`, `PWD` and `OLDPWD`. Command lookup also uses only the fixed safe
directories, never the caller's `PATH`.

This is LeopardOS code under the ISC license; the interface and spirit follow
OpenBSD doas.
