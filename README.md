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

This is LeopardOS code under the ISC license; the interface and spirit follow
OpenBSD doas.
