#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define SOCK_PATH "/data/local/tmp/.rs"

static int daemonize(void)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p > 0) _exit(0);
    setsid();
    p = fork();
    if (p > 0) _exit(0);
    chdir("/");
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) { dup2(fd, 0); dup2(fd, 1); dup2(fd, 2); if (fd > 2) close(fd); }
    return 0;
}

static int run_daemon(void)
{
    if (daemonize() < 0) return 1;

    unlink(SOCK_PATH);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) return 1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SOCK_PATH, sizeof(sa.sun_path) - 1);
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0) return 1;
    chmod(SOCK_PATH, 0666);
    if (listen(ls, 8) < 0) return 1;

    signal(SIGCHLD, SIG_IGN);
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) { usleep(10000); continue; }
        pid_t p = fork();
        if (p == 0) {
            close(ls);
            dup2(c, 0); dup2(c, 1); dup2(c, 2);
            if (c > 2) close(c);
            setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
            setenv("HOME", "/", 1);
            setenv("TERM", "xterm", 1);
            execl("/system/bin/sh", "sh", "-i", NULL);
            _exit(1);
        }
        close(c);
    }
}

static int run_client(int argc, char **argv)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SOCK_PATH, sizeof(sa.sun_path) - 1);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("connect"); return 1; }

    if (argc > 1) {
        char cmd[4096] = {0};
        for (int i = 1; i < argc; i++) {
            strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 2);
            if (i + 1 < argc) strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 2);
        }
        strncat(cmd, "\n", sizeof(cmd) - strlen(cmd) - 2);
        write(s, cmd, strlen(cmd));
        shutdown(s, SHUT_WR);
        char buf[4096];
        ssize_t n;
        while ((n = read(s, buf, sizeof(buf))) > 0) write(1, buf, n);
        return 0;
    }

    /* interactive: forward both directions */
    struct pollfd pfd[2];
    pfd[0].fd = 0; pfd[0].events = POLLIN;
    pfd[1].fd = s; pfd[1].events = POLLIN;
    char buf[4096];
    for (;;) {
        int r = poll(pfd, 2, -1);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (pfd[0].revents & POLLIN) {
            ssize_t n = read(0, buf, sizeof(buf));
            if (n <= 0) { shutdown(s, SHUT_WR); pfd[0].fd = -1; continue; }
            if (write(s, buf, n) < 0) break;
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t n = read(s, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(1, buf, n) < 0) break;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "-d") == 0) return run_daemon();
    return run_client(argc, argv);
}
