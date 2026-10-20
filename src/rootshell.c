/*
 * rootshell —— unix socket root shell 的守护进程 + 客户端。
 *
 * 守护进程由内核 payload 拉起（uid 0、全 capability、u:r:kernel:s0）。
 * 按 argv[0] 分两种角色：
 *
 *   rootshell            客户端：交互 shell（或 "rootshell CMD"）
 *   rootshell -d         守护进程
 *   su [-c CMD]          客户端（安装为 /sbin/su）
 *   su -v / --version    版本号，不连接守护进程
 *
 * 协议（一行头 + 原始字节）：
 *   "S\n"                -> 守护进程在 socket 上跑 /system/bin/sh -i
 *   "E <len>\n" + bytes  -> 守护进程执行 `sh -c <cmd>`，回 "R <outlen> <code>\n"
 *                           + 输出，然后关闭
 *
 * 为什么必须走守护进程：应用执行 setuid 二进制时只能拿到应用的
 * capability bounding set（Android 上是 0xc0），绕不过 DAC；守护进程持有
 * 全量（0x3fffffffff），才能做真正的 root 操作。
 */
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
#define MAX_OUT   (4 * 1024 * 1024)

static ssize_t read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0) return r < 0 ? r : (ssize_t)got;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static ssize_t write_full(int fd, const void *buf, size_t n)
{
    size_t put = 0;
    while (put < n) {
        ssize_t r = write(fd, (const char *)buf + put, n - put);
        if (r <= 0) return r;
        put += (size_t)r;
    }
    return (ssize_t)put;
}

/* 读一行（到 '\n' 为止），返回不含换行的长度 */
static int read_line(int fd, char *buf, size_t cap)
{
    size_t i = 0;
    while (i + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') { buf[i] = 0; return (int)i; }
        buf[i++] = c;
    }
    buf[cap - 1] = 0;
    return -1;
}

/* ---------------- 守护进程 ---------------- */

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

static void run_shell(int c)
{
    dup2(c, 0); dup2(c, 1); dup2(c, 2);
    if (c > 2) close(c);
    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
    setenv("HOME", "/", 1);
    setenv("TERM", "xterm", 1);
    execl("/system/bin/sh", "sh", "-i", NULL);
    _exit(127);
}

static void run_exec(int c, const char *cmd)
{
    int p[2];
    if (pipe(p) != 0) return;

    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1); dup2(p[1], 2);
        close(p[0]); close(p[1]);
        setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
        setenv("HOME", "/", 1);
        execl("/system/bin/sh", "sh", "-c", cmd, NULL);
        _exit(127);
    }
    close(p[1]);

    size_t cap = 65536, len = 0;
    char *buf = malloc(cap);
    int status = 0;
    if (buf) {
        for (;;) {
            if (len == cap) {
                if (cap >= MAX_OUT) break;
                cap *= 2;
                char *nb = realloc(buf, cap);
                if (!nb) break;
                buf = nb;
            }
            ssize_t n = read(p[0], buf + len, cap - len);
            if (n <= 0) break;
            len += (size_t)n;
        }
    }
    close(p[0]);
    waitpid(pid, &status, 0);

    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    char rsp[64];
    int rl = snprintf(rsp, sizeof(rsp), "R %zu %d\n", len, code);
    write_full(c, rsp, (size_t)rl);
    if (len && buf) write_full(c, buf, len);
    free(buf);
}

static void handle_conn(int c)
{
    char hdr[64];
    if (read_line(c, hdr, sizeof(hdr)) < 0) { close(c); return; }

    if (hdr[0] == 'E' && hdr[1] == ' ') {
        long len = atol(hdr + 2);
        if (len <= 0 || len > 65536) { close(c); return; }
        char *cmd = malloc((size_t)len + 1);
        if (!cmd) { close(c); return; }
        if (read_full(c, cmd, (size_t)len) != len) { free(cmd); close(c); return; }
        cmd[len] = 0;
        run_exec(c, cmd);
        free(cmd);
    } else {
        run_shell(c);          /* "S"，或任何未知头：进入交互 shell */
    }
    close(c);
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

    signal(SIGCHLD, SIG_DFL);
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) { usleep(10000); continue; }
        if (fork() == 0) { close(ls); handle_conn(c); _exit(0); }
        close(c);
        /* 回收已结束的连接处理进程，避免僵尸；run_exec 自己的 waitpid 不受影响 */
        while (waitpid(-1, NULL, WNOHANG) > 0) { }
    }
}

/* ---------------- 客户端 ---------------- */

static int connect_daemon(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SOCK_PATH, sizeof(sa.sun_path) - 1);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(s); return -1; }
    return s;
}

static int client_exec(const char *cmd)
{
    int s = connect_daemon();
    if (s < 0) { fprintf(stderr, "su: 守护进程没在跑（先跑 deploy.py）\n"); return 1; }

    char hdr[32];
    int hl = snprintf(hdr, sizeof(hdr), "E %zu\n", strlen(cmd));
    if (write_full(s, hdr, (size_t)hl) < 0 ||
        write_full(s, cmd, strlen(cmd)) < 0) {
        close(s);
        return 1;
    }
    shutdown(s, SHUT_WR);

    char rsp[64];
    if (read_line(s, rsp, sizeof(rsp)) < 0 || rsp[0] != 'R') {
        fprintf(stderr, "su: 守护进程回应异常\n");
        close(s);
        return 1;
    }
    size_t outlen = 0;
    int code = 1;
    sscanf(rsp + 2, "%zu %d", &outlen, &code);

    char buf[4096];
    while (outlen > 0) {
        size_t want = outlen < sizeof(buf) ? outlen : sizeof(buf);
        ssize_t n = read(s, buf, want);
        if (n <= 0) break;
        write_full(1, buf, (size_t)n);
        outlen -= (size_t)n;
    }
    close(s);
    return code;
}

static int client_shell(void)
{
    int s = connect_daemon();
    if (s < 0) { fprintf(stderr, "rootshell: 守护进程没在跑（先跑 deploy.py）\n"); return 1; }
    if (write_full(s, "S\n", 2) < 0) { close(s); return 1; }

    struct pollfd pfd[2];
    pfd[0].fd = 0; pfd[0].events = POLLIN;
    pfd[1].fd = s; pfd[1].events = POLLIN;

    char buf[4096];
    for (;;) {
        int r = poll(pfd, 2, -1);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (pfd[0].fd >= 0 && (pfd[0].revents & (POLLIN | POLLHUP))) {
            ssize_t n = read(0, buf, sizeof(buf));
            if (n <= 0) { shutdown(s, SHUT_WR); pfd[0].fd = -1; continue; }
            if (write_full(s, buf, (size_t)n) < 0) break;
        }
        if (pfd[1].revents & (POLLIN | POLLHUP)) {
            ssize_t n = read(s, buf, sizeof(buf));
            if (n <= 0) break;
            write_full(1, buf, (size_t)n);
        }
    }
    close(s);
    return 0;
}

/* ---------------- 入口 ---------------- */

static const char *prog_name(const char *argv0)
{
    const char *p = strrchr(argv0, '/');
    return p ? p + 1 : argv0;
}

static const char *join_args(int argc, char **argv, int from)
{
    static char buf[4096];
    size_t off = 0;
    buf[0] = 0;
    for (int i = from; i < argc; i++) {
        size_t n = strlen(argv[i]);
        if (off + n + 2 >= sizeof(buf)) break;
        if (off) buf[off++] = ' ';
        memcpy(buf + off, argv[i], n);
        off += n;
        buf[off] = 0;
    }
    return buf;
}

int main(int argc, char **argv)
{
    const char *prog = prog_name(argv[0]);

    if (!strcmp(prog, "su")) {
        if (argc >= 2 && (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version"))) {
            puts("su 1.0 (old-phone-temp-root)");
            return 0;
        }
        if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
            puts("用法: su [-c 命令] | su [-v]");
            return 0;
        }
        int i = 1;
        if (i < argc && !strcmp(argv[i], "0")) i++;          /* su 0 -c ... */
        if (i < argc && !strcmp(argv[i], "-s")) i += 2;      /* su -s SHELL -c ... */
        if (i < argc && !strcmp(argv[i], "-c")) {
            if (i + 1 < argc) return client_exec(join_args(argc, argv, i + 1));
            fprintf(stderr, "su: -c 需要参数\n");
            return 1;
        }
        return client_shell();
    }

    if (argc > 1 && !strcmp(argv[1], "-d")) return run_daemon();
    if (argc > 1) return client_exec(join_args(argc, argv, 1));
    return client_shell();
}
