/*
 * doas — minimal privilege elevation, inspired by OpenBSD doas.
 *
 * Installed setuid root (04755).  The kernel applies S_ISUID during exec, so
 * this process starts with the Root XUT identity.  It authenticates the
 * invoking account's password through SXAH_CHECK_USER_PASSWORD (the only
 * kernel primitive, root-only), then execs the target command, which inherits
 * the elevated identity.
 *
 * Config: /system/config/doas.conf, falling back to /config/doas.conf.
 * If no file exists, Admin users are permitted.  Root never needs a password.
 * The config must be owned by uid 0 and not group/world writable; anything
 * else is refused outright instead of falling back to the default.
 *
 * The target command never inherits the caller's environment.  Only a small
 * whitelist of display/locale variables survives; PATH, USER, LOGNAME and
 * HOME are replaced with fixed values.
 */
#include "xtuiapi.h"
#include "libsys.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define SXAH_CHECK_USER_PASSWORD 128956723895689203ULL

#ifndef TCGETS
#define TCGETS 0x5401
#endif
#ifndef TCSETS
#define TCSETS 0x5402
#endif
#ifndef ECHO
#define ECHO 0000010
#endif
#ifndef X_OK
#define X_OK 1
#endif

#define CONFIG_PATH_SYSTEM "/system/config/doas.conf"
#define CONFIG_PATH_LIVE   "/config/doas.conf"
#define PATH_CAP           512

/* Safe search path; also the PATH exported to the target command. */
#define SAFE_PATH "/apps/system:/apps/leopard:/apps/builtin:/system/leopard"

#define CONFIG_MISSING  (-1)
#define CONFIG_INSECURE (-2)

/* Hard cap on the child environment; no unbounded growth. */
#define ENV_CAP   32
#define ENV_ARENA 4096

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

struct doas_termios {
        uint32_t c_iflag;
        uint32_t c_oflag;
        uint32_t c_cflag;
        uint32_t c_lflag;
        uint8_t  c_line;
        uint8_t  c_cc[20];
};

static void out_fd(int fd, const char *text)
{
        if (text != NULL && text[0] != '\0')
                (void)write(fd, text, strlen(text));
}

static int read_password(char *buffer, size_t capacity)
{
        struct doas_termios saved;
        struct doas_termios term;
        int    restore = 0;
        size_t length = 0;

        if (buffer == NULL || capacity == 0) return -1;
        buffer[0] = '\0';

        if (ioctl(0, TCGETS, &term) == 0) {
                saved = term;
                term.c_lflag &= ~((uint32_t)ECHO);
                if (ioctl(0, TCSETS, &term) == 0) restore = 1;
        } else {
                out_fd(2, "doas: no controlling terminal\n");
                return -1;
        }

        for (;;) {
                char    ch;
                ssize_t got = read(0, &ch, 1);
                if (got < 0) {
                        if (errno == EINTR) continue;
                        break;
                }
                if (got == 0 || ch == '\n' || ch == '\r') break;
                if (ch == '\b' || ch == 0x7f) {
                        if (length > 0) length--;
                        continue;
                }
                if (length + 1 < capacity) buffer[length++] = ch;
        }
        buffer[length] = '\0';
        out_fd(1, "\n");

        if (restore) (void)ioctl(0, TCSETS, &saved);
        return (int)length;
}

static void wipe(char *buffer, size_t length)
{
        while (length-- > 0) buffer[length] = '\0';
}

/*
 * Read one config file into memory.
 *
 * Returns the length on success, CONFIG_MISSING if the file does not exist,
 * or CONFIG_INSECURE if it cannot be trusted.  The ownership/mode check is
 * done with fstat() on the descriptor we actually read, so the path cannot be
 * swapped between check and read.  O_NOFOLLOW is honoured where the libc and
 * kernel support it; fstat() still validates whatever was opened.
 */
static int read_config(const char *path, char *buffer, size_t capacity)
{
        struct stat st;
        int     fd;
        ssize_t got;

        if (path == NULL || buffer == NULL || capacity == 0)
                return CONFIG_MISSING;

        fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) {
                /* Only a genuinely absent config may fall through to the
                 * default; any other open failure is a hard error. */
                if (errno == ENOENT || errno == ENOTDIR)
                        return CONFIG_MISSING;
                return CONFIG_INSECURE;
        }

        if (fstat(fd, &st) != 0 ||
            st.st_uid != 0 ||
            (st.st_mode & 022) != 0 ||
            !S_ISREG(st.st_mode)) {
                close(fd);
                return CONFIG_INSECURE;
        }

        got = read(fd, buffer, capacity - 1);
        close(fd);
        if (got < 0) return CONFIG_INSECURE;
        buffer[got] = '\0';
        return (int)got;
}

/*
 * Load the first available config.  Returns its length, CONFIG_MISSING when
 * neither path exists, or CONFIG_INSECURE when a file exists but fails the
 * ownership/mode check.  An insecure system config never falls back to the
 * live path.
 */
static int load_config(char *buffer, size_t capacity)
{
        int got;

        got = read_config(CONFIG_PATH_SYSTEM, buffer, capacity);
        if (got != CONFIG_MISSING) return got;
        return read_config(CONFIG_PATH_LIVE, buffer, capacity);
}

/*
 * Returns 1 if the caller is permitted, 0 if denied.  An absent config keeps
 * the Admin-only default; CONFIG_INSECURE is handled by the caller before
 * this point and denies everything.
 */
static int config_permits(const char *name, UserType type, char *buffer, int got)
{
        if (buffer == NULL || got < 0)
                return got == CONFIG_MISSING ? type == XUT_Admin : 0;
        if (name == NULL) return 0;

        char *line = buffer;
        while (*line != '\0') {
                char *end = strchr(line, '\n');
                if (end != NULL) *end = '\0';

                char *p = line;
                while (*p == ' ' || *p == '\t' || *p == '\r') p++;
                if (*p == '#' || *p == '\0') {
                        if (end == NULL) break;
                        line = end + 1;
                        continue;
                }

                char *tok[4] = { NULL, NULL, NULL, NULL };
                int   ntok = 0;
                for (char *t = strtok(p, " \t\r"); t != NULL && ntok < 4; t = strtok(NULL, " \t\r"))
                        tok[ntok++] = t;

                if (ntok >= 2 && strcmp(tok[0], "permit") == 0) {
                        if (strcmp(tok[1], "admin") == 0 && type == XUT_Admin) return 1;
                        if (strcmp(tok[1], "root") == 0 && type == XUT_Root) return 1;
                        if (strcmp(tok[1], "system") == 0 && type == XUT_System) return 1;
                        if (strcmp(tok[1], "user") == 0 && ntok >= 3 && strcmp(tok[2], name) == 0) return 1;
                        if (strcmp(tok[1], name) == 0) return 1;
                }

                if (end == NULL) break;
                line = end + 1;
        }
        return 0;
}

/*
 * Fixed-capacity child environment.  Strings are copied into a fixed arena;
 * no caller pointer is ever passed to execve() and no unbounded allocation is
 * performed.
 */
struct child_env {
        char  *vec[ENV_CAP + 1];
        char   data[ENV_ARENA];
        size_t used;
        size_t count;
};

static int env_name_is(const char *entry, const char *name)
{
        size_t len = strlen(name);

        return strncmp(entry, name, len) == 0 && entry[len] == '=';
}

/* Only display and locale variables survive from the caller's environment. */
static int env_allowed(const char *entry)
{
        static const char *const keep[] = {
                "TERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
                "LC_COLLATE", "LC_NUMERIC", "LC_TIME", "COLORTERM", NULL
        };

        if (entry == NULL) return 0;
        for (int i = 0; keep[i] != NULL; i++)
                if (env_name_is(entry, keep[i])) return 1;
        return 0;
}

static int env_push(struct child_env *env, const char *entry)
{
        size_t len;

        if (entry == NULL || env->count >= ENV_CAP) return -1;
        len = strlen(entry);
        if (env->used + len + 1 > sizeof(env->data)) return -1;

        memcpy(env->data + env->used, entry, len + 1);
        env->vec[env->count++] = env->data + env->used;
        env->used += len + 1;
        env->vec[env->count] = NULL;
        return 0;
}

static int build_env(struct child_env *env, char *const caller_envp[])
{
        static const char *const fixed[] = {
                "PATH=" SAFE_PATH,
                "USER=root",
                "LOGNAME=root",
                "HOME=/",
                NULL
        };

        memset(env, 0, sizeof(*env));
        for (int i = 0; fixed[i] != NULL; i++)
                if (env_push(env, fixed[i]) != 0) return -1;

        /* LD_*, IFS, ENV, BASH_ENV, SHELL, PWD, OLDPWD and everything else
         * are dropped: they are not on the whitelist above. */
        for (size_t i = 0; caller_envp != NULL && caller_envp[i] != NULL; i++) {
                if (!env_allowed(caller_envp[i])) continue;
                (void)env_push(env, caller_envp[i]);
        }
        return 0;
}

static int find_command(const char *name, char *out, size_t cap)
{
        static const char *const dirs[] = {
                "/apps/system", "/apps/leopard", "/apps/builtin", "/system/leopard", NULL
        };

        if (name == NULL || name[0] == '\0') return -1;
        if (strchr(name, '/') != NULL) {
                if (access(name, X_OK) == 0) {
                        strncpy(out, name, cap - 1);
                        out[cap - 1] = '\0';
                        return 0;
                }
                return -1;
        }

        /* Search only the fixed safe directories; never the caller's PATH. */
        for (int i = 0; dirs[i] != NULL; i++) {
                snprintf(out, cap, "%s/%s", dirs[i], name);
                if (access(out, X_OK) == 0) return 0;
                snprintf(out, cap, "%s/%s.elf", dirs[i], name);
                if (access(out, X_OK) == 0) return 0;
        }
        return -1;
}

int main(int argc, char *argv[], char *envp[])
{
        UserInfo current;
        struct child_env env;
        char     config[4096];
        int      config_len;
        int      command_index = 1;

        if (argc < 2) {
                out_fd(2, "usage: doas [-u root] command [args...]\n");
                return 2;
        }

        if (strcmp(argv[1], "-u") == 0) {
                if (argc < 4) {
                        out_fd(2, "doas: -u requires a user and a command\n");
                        return 2;
                }
                if (strcmp(argv[2], "root") != 0) {
                        out_fd(2, "doas: only -u root is supported\n");
                        return 2;
                }
                command_index = 3;
        } else if (argv[1][0] == '-') {
                out_fd(2, "usage: doas [-u root] command [args...]\n");
                return 2;
        }

        memset(&current, 0, sizeof(current));
        xapi_GetCurrentUser(&current);

        /* Fail closed for every caller, root included: a config that exists
         * but is not owned by uid 0 or is group/world-writable denies all
         * requests. */
        config_len = load_config(config, sizeof(config));
        if (config_len == CONFIG_INSECURE) {
                out_fd(2, "doas: insecure config file\n");
                return 1;
        }

        if (current.user_type != XUT_Root) {
                if (!config_permits(current.name, current.user_type,
                                    config, config_len)) {
                        out_fd(2, "doas: permission denied\n");
                        return 1;
                }
                if (geteuid() != 0) {
                        out_fd(2, "doas: not installed setuid root\n");
                        return 1;
                }

                char password[128];
                char prompt[160];

                snprintf(prompt, sizeof(prompt), "doas: password for %s: ", current.name);
                out_fd(1, prompt);
                if (read_password(password, sizeof(password)) < 0) {
                        wipe(password, sizeof(password));
                        return 1;
                }

                int64_t result = (int64_t)enter_syscall(SXAH_CHECK_USER_PASSWORD,
                                                        (uint64_t)current.name,
                                                        (uint64_t)password, 0, 0, 0, 0);
                wipe(password, sizeof(password));
                if (result != 0) {
                        out_fd(2, "doas: authentication failed\n");
                        return 1;
                }
        }

        char path[PATH_CAP];
        if (find_command(argv[command_index], path, sizeof(path)) != 0) {
                out_fd(2, "doas: command not found\n");
                return 1;
        }

        if (build_env(&env, envp) != 0) {
                out_fd(2, "doas: cannot build a safe environment\n");
                return 1;
        }

        execve(path, &argv[command_index], env.vec);
        out_fd(2, "doas: cannot execute command\n");
        return 1;
}
