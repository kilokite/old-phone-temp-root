/*
 * su — minimal setuid-root shell for the tmpfs overlay.
 *
 * Installed by the kernel payload at /data/local/tmp/.su/su with mode 4755.
 * /data is mounted nosuid, so the binary must live on a tmpfs that we mount
 * ourselves (see payload/wb.sh).  SELinux is permissive by the time this runs,
 * so no domain transition is required.
 *
 * Usage:  su [-c "command"]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>

int main(int argc, char **argv)
{
    if (setgroups(0, NULL) != 0) {
        /* non-fatal when already uid 0 without CAP_SETGID */
    }
    if (setgid(0) != 0 || setuid(0) != 0 || geteuid() != 0) {
        fprintf(stderr, "su: cannot become root: %s\n", strerror(errno));
        return 1;
    }

    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
    setenv("HOME", "/", 1);
    setenv("TERM", "xterm", 1);

    const char *cmd = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            cmd = argv[i + 1];
            break;
        }
    }

    if (cmd)
        execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    else
        execl("/system/bin/sh", "sh", (char *)NULL);

    perror("su: exec");
    return 1;
}
