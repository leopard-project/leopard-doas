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
#define LINE_CAP           256

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

/* Read one config file into memory; returns length or -1. */
static int read_config(const char *path, char *buffer, size_t capacity)
{
        int     fd;
        ssize_t got;

        if (path == NULL || buffer == NULL || capacity == 0) return -1;
        fd = open(path, O_RDONLY);
        if (fd < 0) return -1;
        got = read(fd, buffer, capacity - 1);
        close(fd);
        if (got < 0) return -1;
        buffer[got] = '\0';
        return (int)got;
}

/* Returns 1 if the caller is permitted, 0 otherwise. */
static int config_permits(const char *name, UserType type)
{
        char buffer[4096];
        int  got;

        if (name == NULL) return 0;

        got = read_config(CONFIG_PATH_SYSTEM, buffer, sizeof(buffer));
        if (got < 0) got = read_config(CONFIG_PATH_LIVE, buffer, sizeof(buffer));
        if (got < 0) {
                /* No config: the default is Admin-only. */
                return type == XUT_Admin;
        }

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

        for (int i = 0; dirs[i] != NULL; i++) {
                snprintf(out, cap, "%s/%s", dirs[i], name);
                if (access(out, X_OK) == 0) return 0;
                snprintf(out, cap, "%s/%s.elf", dirs[i], name);
                if (access(out, X_OK) == 0) return 0;
        }

        const char *path = getenv("PATH");
        while (path != NULL && *path != '\0') {
                const char *colon = strchr(path, ':');
                size_t      len = colon != NULL ? (size_t)(colon - path) : strlen(path);
                if (len > 0 && len + strlen(name) + 2 < cap) {
                        memcpy(out, path, len);
                        out[len] = '/';
                        strcpy(out + len + 1, name);
                        if (access(out, X_OK) == 0) return 0;
                }
                if (colon == NULL) break;
                path = colon + 1;
        }
        return -1;
}

int main(int argc, char *argv[], char *envp[])
{
        UserInfo current;
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

        if (current.user_type != XUT_Root) {
                if (!config_permits(current.name, current.user_type)) {
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

        execve(path, &argv[command_index], envp);
        out_fd(2, "doas: cannot execute command\n");
        return 1;
}
