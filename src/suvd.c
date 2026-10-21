/*
 * suvd —— 临时 root 的授权守护进程（外加多调用 su 客户端）。
 *
 * 设计目标和老机器的兼容性：
 *   · 不依赖 setuid（/data 是 nosuid，tmpfs 上的 setuid 在部分 ROM 上会被丢），
 *     su 客户端以调用者的 uid 运行，只是连一个 unix socket；
 *   · 一切提权动作都发生在守护进程里（uid 0、全 capability、u:r:kernel:s0），
 *     客户端拿到的输出就是真正的 root 输出；
 *   · 授权由手机上的管理 App 弹窗决定（守护进程用 am start 拉起它），
 *     默认拒绝，超时拒绝；可以「仅本次 / 永久」记住。
 *
 * 角色（按 argv[0] 判定）：
 *   suvd -d [选项]        守护进程
 *   su   -c "命令"        客户端（wb.sh 会把 /sbin/su 做成指向 suvd 的链接）
 *   suvd -t               触发 request_module（socket(30)），用于部署脚本
 *   suvd -V / --version   版本
 *   suvd --status         打印守护进程状态
 *
 * 客户端协议（一行头 + 可选原始字节；所有回复都以一行开头）：
 *   "V\n"                        -> "V <ver> <manager_uid> <timeout> <default>\n"
 *   "Q <len>\n" + cmd            -> "O\n" + 原始输出 + "\n__SUVX_<nonce>_<code>__\n"
 *                                 | "D <原因>\n" | "E <错误>\n"
 *   "S\n"                        -> "O\n" + 交互式 sh；| "D <原因>\n"
 *   "L\n"                        -> "L <len>\n" + "uid\tmode\n"...（管理员）
 *   "P <uid> <allow|deny>\n"     -> "OK\n"（管理员）
 *   "X <uid>\n"                  -> "OK\n"（管理员）
 *   "Z\n"                        -> "OK\n"（管理员，清空全部授权）
 *   "K\n"                        -> "OK\n"（管理员，停止守护进程）
 *   "A <id> <token> <decision>\n"-> "OK\n"（弹窗应答；凭 id+token 认证）
 *
 * 授权策略文件：<base>/policy.tsv，每行 "uid\tmode\n"，mode = allow | deny。
 * 日志：<base>/suvd.log（超过 512KB 轮转为 .1）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <poll.h>
#include <stdint.h>

#define SUV_VERSION      "1.0"
#define SUV_TAG          "OldRootSU"
#define COMPAT_VERSION   "2.82:SUPERSU"     /* 老 App 认这个字符串 */
#define MAX_CMD          (256 * 1024)
#define MAX_HDR          512
#define MAX_POLICY       2048
#define LOG_MAX          (512 * 1024)
#define DEF_TIMEOUT      60
#define MAX_ALLOW_UID    8
#define PENDING_MAX      64

#ifndef SO_PEERCRED
#define SO_PEERCRED 17
#endif

/* ---------------- 配置 ---------------- */

struct cfg {
    char base[256];
    char sock[320];
    char policy[320];
    char log[320];
    char lock[320];
    char pending[320];
    char pidfile[320];
    char packages_list[64];
    char manager[160];
    int  manager_uid;
    int  timeout;
    int  restart;
    int  allow_uid[MAX_ALLOW_UID];
    int  nallow;
} C;

static int g_verbose = 0;
static int g_shell_log = 0;      /* --debug-shell：把 shell 输入输出写日志（排查兼容性用） */
static int g_argc = 0;
static char **g_argv = NULL;

/* 调用方通过 H 头送来的 argv / 环境（每个 handler 进程独立，fork 后安全） */
static char   g_argblob[2048];
static size_t g_arglen = 0;
static char   g_envblob[8192];
static size_t g_envlen = 0;

static const char *env_get(const char *key);

/* ---------------- 基础 I/O ---------------- */

static ssize_t write_all(int fd, const void *buf, size_t n)
{
    size_t put = 0;
    while (put < n) {
        ssize_t r = write(fd, (const char *)buf + put, n - put);
        if (r < 0) {
            if (errno == EINTR) continue;
            return r;
        }
        if (r == 0) break;
        put += (size_t)r;
    }
    return (ssize_t)put;
}

static ssize_t read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return r;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

/* 读一行（不含 '\n'）；超长或 EOF 返回 -1 */
static int read_line(int fd, char *buf, size_t cap)
{
    size_t i = 0;
    while (i + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        if (c == '\n') { buf[i] = 0; return (int)i; }
        buf[i++] = c;
    }
    buf[cap - 1] = 0;
    return -1;
}

static void sendf(int fd, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) write_all(fd, buf, (size_t)n);
}

/* ---------------- 随机数 / 日志 ---------------- */

static void random_hex(char *out, int bytes)
{
    static const char hx[] = "0123456789abcdef";
    unsigned char buf[64];
    int got = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        got = (int)read_full(fd, buf, (size_t)bytes);
        close(fd);
    }
    if (got < bytes) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned long seed = (unsigned long)tv.tv_usec ^ ((unsigned long)getpid() << 16)
                           ^ (unsigned long)time(NULL) ^ (unsigned long)(uintptr_t)out;
        for (int i = got; i < bytes; i++) {
            seed = seed * 6364136223846793005UL + 1442695040888963407UL;
            buf[i] = (unsigned char)(seed >> 33);
        }
    }
    for (int i = 0; i < bytes; i++) {
        out[i * 2]     = hx[buf[i] >> 4];
        out[i * 2 + 1] = hx[buf[i] & 15];
    }
    out[bytes * 2] = 0;
}

static void rotate_log(void)
{
    struct stat st;
    if (stat(C.log, &st) != 0) return;
    if (st.st_size < LOG_MAX) return;
    char old[340];
    snprintf(old, sizeof(old), "%s.1", C.log);
    unlink(old);
    rename(C.log, old);
}

static void dlog(const char *fmt, ...)
{
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    rotate_log();

    int fd = open(C.log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char line[2300];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    int n = snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d %s\n",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec, msg);
    if (n > 0) write_all(fd, line, (size_t)n);
    close(fd);
    if (g_verbose) {
        fprintf(stderr, "%s\n", msg);
        fflush(stderr);
    }
}

/* ---------------- 策略 ---------------- */

struct pent { int uid; int mode; };
static int policy_read(struct pent *out, int cap)
{
    FILE *f = fopen(C.policy, "r");
    if (!f) return 0;
    char line[128];
    int n = 0;
    while (n < cap && fgets(line, sizeof(line), f)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = 0;
        int uid = atoi(line);
        if (uid <= 0) continue;
        const char *mode = tab + 1;
        int m = 0;
        if (!strncmp(mode, "allow", 5)) m = 1;
        else if (!strncmp(mode, "deny", 4)) m = 2;
        if (!m) continue;
        int dup = 0;
        for (int i = 0; i < n; i++) if (out[i].uid == uid) { out[i].mode = m; dup = 1; break; }
        if (!dup) { out[n].uid = uid; out[n].mode = m; n++; }
    }
    fclose(f);
    return n;
}

static int policy_lookup(int uid)
{
    struct pent e[MAX_POLICY];
    int n = policy_read(e, MAX_POLICY);
    for (int i = 0; i < n; i++) if (e[i].uid == uid) return e[i].mode;
    return 0;
}

static int policy_write(struct pent *e, int n)
{
    char tmp[340];
    snprintf(tmp, sizeof(tmp), "%s.tmp", C.policy);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    char buf[64];
    for (int i = 0; i < n; i++) {
        int k = snprintf(buf, sizeof(buf), "%d\t%s\n", e[i].uid,
                         e[i].mode == 1 ? "allow" : "deny");
        if (write_all(fd, buf, (size_t)k) != k) { close(fd); unlink(tmp); return -1; }
    }
    fsync(fd);
    close(fd);
    chmod(tmp, 0644);
    if (rename(tmp, C.policy) != 0) { unlink(tmp); return -1; }
    return 0;
}

/* mode: 1=allow 2=deny 0=删除 */
static int policy_modify(int uid, int mode)
{
    int lk = open(C.lock, O_CREAT | O_RDWR, 0600);
    if (lk >= 0) flock(lk, LOCK_EX);

    struct pent e[MAX_POLICY];
    int n = policy_read(e, MAX_POLICY);
    int idx = -1;
    for (int i = 0; i < n; i++) if (e[i].uid == uid) { idx = i; break; }

    int rc;
    if (mode == 0) {
        if (idx < 0) { rc = 0; goto done; }
        memmove(&e[idx], &e[idx + 1], sizeof(e[0]) * (size_t)(n - idx - 1));
        n--;
    } else if (idx >= 0) {
        e[idx].mode = mode;
    } else {
        if (n >= MAX_POLICY) { rc = -1; goto done; }
        e[n].uid = uid;
        e[n].mode = mode;
        n++;
    }
    rc = policy_write(e, n);
done:
    if (lk >= 0) { flock(lk, LOCK_UN); close(lk); }
    return rc;
}

/* ---------------- 进程 / 身份 ---------------- */

static int peer_uid(int fd)
{
    struct ucred cr;
    socklen_t len = sizeof(cr);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0) return -1;
    return (int)cr.uid;
}

static int is_manager(int uid)
{
    return C.manager_uid > 0 && uid == C.manager_uid;
}

static int is_admin(int uid)
{
    return uid == 0 || is_manager(uid);
}

static void become_root(void)
{
    setgroups(0, NULL);
    setgid(0);
    setuid(0);
}

static void set_root_env(void)
{
    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
    setenv("HOME", "/", 1);
    setenv("TERM", "xterm", 1);
    setenv("ANDROID_ROOT", "/system", 0);
    setenv("ANDROID_DATA", "/data", 0);
}

/*
 * 把调用方的环境变量原样带进 root 进程。真实 su 也是保留调用方环境的；
 * MT 管理器这类应用会依赖自己的 PATH / LD_LIBRARY_PATH / TMPDIR，
 * 丢环境会让它判定「root 不可用」。
 */
static void apply_client_env(void)
{
    if (g_envlen == 0) return;
    char *p = g_envblob;
    char *end = g_envblob + g_envlen;
    while (p < end) {
        size_t len = strlen(p);
        if (len == 0) break;
        char *eq = strchr(p, '=');
        if (eq) {
            *eq = 0;
            setenv(p, eq + 1, 1);
            *eq = '=';
        }
        p += len + 1;
    }
}

static void set_default_env(void)
{
    if (!getenv("PATH") || !getenv("PATH")[0])
        setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin", 1);
    if (!getenv("HOME")) setenv("HOME", "/", 1);
    if (!getenv("TERM")) setenv("TERM", "xterm", 1);
    if (!getenv("ANDROID_ROOT")) setenv("ANDROID_ROOT", "/system", 1);
    if (!getenv("ANDROID_DATA")) setenv("ANDROID_DATA", "/data", 1);
}

/*
 * root 进程用 u:r:shell:s0 执行。
 * kernel 域访问不到 service_manager（pm/am 会报 Can't connect to ...），
 * 而 shell 域可以；uid 仍是 0、capability 全量，文件操作不受影响。
 * 写 /proc/self/attr/exec 失败（例如 SELinux 非 permissive）时保持原域。
 */
static void set_shell_exec_context(void)
{
    int fd = open("/proc/self/attr/exec", O_WRONLY);
    if (fd < 0) return;
    const char *ctx = "u:r:shell:s0";
    ssize_t w = write(fd, ctx, strlen(ctx));
    (void)w;
    close(fd);
}

/*
 * 守护进程由内核 call_usermodehelper 拉起，环境是空的；am 需要 BOOTCLASSPATH
 * 才能启动 app_process。root 可以读别的进程的 /proc/<pid>/environ，借一份即可。
 */
static void load_bootclasspath(void)
{
    if (getenv("BOOTCLASSPATH") && getenv("BOOTCLASSPATH")[0]) return;

    DIR *d = opendir("/proc");
    if (!d) return;
    static char buf[65536];
    char value[4096];
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        int ispid = 1;
        for (const char *p = de->d_name; *p; p++)
            if (*p < '0' || *p > '9') { ispid = 0; break; }
        if (!ispid) continue;

        char path[300];
        snprintf(path, sizeof(path), "/proc/%s/environ", de->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;

        char *p = buf, *end = buf + n;
        while (p < end) {
            size_t len = strlen(p);
            if (!strncmp(p, "BOOTCLASSPATH=", 14) && len > 14) {
                snprintf(value, sizeof(value), "%s", p + 14);
                setenv("BOOTCLASSPATH", value, 1);
                closedir(d);
                return;
            }
            p += len + 1;
        }
    }
    closedir(d);
}

static void child_common(int c, int dup_stdin)
{
    become_root();
    apply_client_env();
    set_default_env();
    set_shell_exec_context();
    if (dup_stdin) dup2(c, 0);
    dup2(c, 1);
    dup2(c, 2);
    if (c > 2) close(c);
}

static int wait_status(pid_t p)
{
    int st = 0;
    while (waitpid(p, &st, 0) < 0) {
        if (errno != EINTR) return 128;
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 128;
}

/* ---------------- 管理 App 弹窗 ---------------- */

static void cleanup_pending(const char *id)
{
    char p[400];
    snprintf(p, sizeof(p), "%s/%s.tok", C.pending, id); unlink(p);
    snprintf(p, sizeof(p), "%s/%s.ans", C.pending, id); unlink(p);
}

static int valid_id(const char *s)
{
    if (!s || !*s || strlen(s) > 64) return 0;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.') return 0;
    return 1;
}

/*
 * 拉起授权弹窗。
 *
 * 为什么用 am：MIUI 等 ROM 会拦截「后台应用自己 startActivity」
 * （日志：MIUI Permission Denied Activity），但 shell 发起的启动是放行的。
 * 所以守护进程 fork 一个子进程，把 exec 域切成 u:r:shell:s0、降权到
 * uid 2000，再 exec /system/bin/am —— 等同于 `adb shell am start`。
 * app_process 需要 BOOTCLASSPATH，由 load_bootclasspath() 在启动时准备好。
 *
 * 返回 0 = am 成功启动（不等于用户已同意）。
 */
static int launch_prompt(const char *id, const char *token, int uid, const char *cmd)
{
    if (!C.manager[0]) return -1;

    char cls[220];
    snprintf(cls, sizeof(cls), "%s/.PromptActivity", C.manager);

    char cmdshow[520];
    snprintf(cmdshow, sizeof(cmdshow), "%s", cmd);
    for (char *p = cmdshow; *p; p++) if (*p == '\n' || *p == '\r') *p = ' ';
    if (strlen(cmd) >= sizeof(cmdshow)) strncat(cmdshow, "…", sizeof(cmdshow) - strlen(cmdshow) - 1);

    char uids[16], timeos[16];
    snprintf(uids, sizeof(uids), "%d", uid);
    snprintf(timeos, sizeof(timeos), "%d", C.timeout);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int fd = open("/proc/self/attr/exec", O_WRONLY);
        if (fd >= 0) {
            const char *ctx = "u:r:shell:s0";
            ssize_t w = write(fd, ctx, strlen(ctx));
            (void)w;
            close(fd);
        }
        setgid(2000);
        setuid(2000);
        set_root_env();
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        execl("/system/bin/am", "am", "start",
              "-a", "com.oldroot.manager.PROMPT",
              "--es", "id", id,
              "--es", "token", token,
              "--es", "uid", uids,
              "--es", "cmd", cmdshow,
              "--ei", "timeout", timeos,
              "-n", cls,
              (char *)NULL);
        _exit(127);
    }

    int code = -1;
    for (int i = 0; i < 50; i++) {
        int st = 0;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) {
            code = WIFEXITED(st) ? WEXITSTATUS(st) : 128;
            break;
        }
        usleep(100000);
    }
    if (code < 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        code = 124;
    }
    if (code != 0) {
        dlog("prompt: am start 失败（exit=%d），管理 App 是否已安装？", code);
        return -1;
    }
    return 0;
}

/*
 * 返回 1 = 允许，0 = 拒绝（timeout/无应答也拒绝）。
 * always 输出是否要写进策略；why 给出拒绝原因。
 */
static int prompt_user(int uid, const char *cmd, int *always, char *why, size_t whysz)
{
    *always = 0;
    if (!C.manager[0]) {
        snprintf(why, whysz, "守护进程没有配置管理 App");
        return 0;
    }

    char id[80], token[40];
    snprintf(id, sizeof(id), "%d-%ld", (int)getpid(), (long)time(NULL));
    random_hex(token, 16);

    char tokfile[400], ansfile[400];
    snprintf(tokfile, sizeof(tokfile), "%s/%s.tok", C.pending, id);
    snprintf(ansfile, sizeof(ansfile), "%s/%s.ans", C.pending, id);

    int tf = open(tokfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (tf < 0) {
        dlog("prompt: 无法创建 %s: %s", tokfile, strerror(errno));
        return 0;
    }
    write_all(tf, token, strlen(token));
    close(tf);

    dlog("prompt: uid=%d 等待授权 id=%s cmd=\"%.120s\"", uid, id, cmd);
    if (launch_prompt(id, token, uid, cmd) != 0) {
        cleanup_pending(id);
        snprintf(why, whysz, "管理 App 的授权服务没在运行（请打开「老机 Root」）");
        return 0;
    }

    time_t deadline = time(NULL) + C.timeout;
    int answer = 0;
    while (time(NULL) < deadline) {
        int af = open(ansfile, O_RDONLY);
        if (af >= 0) {
            char buf[32] = {0};
            ssize_t r = read(af, buf, sizeof(buf) - 1);
            close(af);
            if (r > 0) {
                int allow = 0, alw = 0;
                if (!strncmp(buf, "allow_always", 12)) { allow = 1; alw = 1; }
                else if (!strncmp(buf, "allow", 5))    { allow = 1; alw = 0; }
                else if (!strncmp(buf, "deny_always", 11)) { allow = 0; alw = 1; }
                else if (!strncmp(buf, "deny", 4))     { allow = 0; alw = 0; }
                else { allow = 0; alw = 0; }
                answer = allow;
                *always = alw;
                dlog("prompt: uid=%d -> %s%s", uid,
                     allow ? "allow" : "deny", alw ? " (always)" : "");
                break;
            }
        }
        usleep(100000);
    }
    if (!answer && *always == 0) {
        int check = open(ansfile, O_RDONLY);
        if (check < 0) {
            dlog("prompt: uid=%d 超时（%ds），按拒绝处理", uid, C.timeout);
            snprintf(why, whysz, "等待授权超时（%d 秒）", C.timeout);
        } else {
            close(check);
            snprintf(why, whysz, "用户拒绝了请求");
        }
    }
    cleanup_pending(id);
    return answer;
}

static int authorize(int uid, const char *cmd, char *why, size_t whysz)
{
    if (uid == 0 || is_manager(uid)) return 1;

    for (int i = 0; i < C.nallow; i++) {
        if (C.allow_uid[i] == uid) return 1;
    }

    int m = policy_lookup(uid);
    if (m == 1) return 1;
    if (m == 2) {
        snprintf(why, whysz, "该应用已被拒绝（可在「老机 Root」里修改）");
        return 0;
    }

    int always = 0;
    int allow = prompt_user(uid, cmd, &always, why, whysz);
    if (always) {
        policy_modify(uid, allow ? 1 : 2);
        dlog("policy: uid=%d 永久%s", uid, allow ? "允许" : "拒绝");
    }
    return allow;
}

/* ---------------- 执行 ---------------- */

static void handle_exec(int c, int uid, const char *cmd)
{
    char why[256] = {0};
    if (!authorize(uid, cmd, why, sizeof(why))) {
        sendf(c, "D %s\n", why[0] ? why : "denied");
        dlog("exec: uid=%d DENY (%s) cmd=\"%.200s\"", uid, why, cmd);
        return;
    }

    char nonce[24];
    random_hex(nonce, 8);
    if (write_all(c, "O\n", 2) != 2) return;

    dlog("exec: uid=%d cmd=\"%.200s\"", uid, cmd);

    pid_t p = fork();
    if (p == 0) {
        child_common(c, 0);
        execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    int code = wait_status(p);
    dlog("exec: uid=%d exit=%d", uid, code);

    sendf(c, "\n__SUVX_%s_%d__\n", nonce, code);
}

static int open_pty(char *slave, size_t n)
{
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0) return -1;
    if (grantpt(m) != 0 || unlockpt(m) != 0) { close(m); return -1; }
    const char *s = ptsname(m);
    if (!s) { close(m); return -1; }
    snprintf(slave, n, "%s", s);
    return m;
}

static void sanitize(char *s)
{
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch < 0x20) *s = ' ';
        else if (ch >= 0x7f) *s = '?';
    }
}

/*
 * 在客户端 socket 和 pty 之间转发，并记录客户端发进来的前 1.5KB 命令，
 * 方便排查「某应用说没 root」时它到底发了什么。
 */
static void relay_shell(int c, int fd, int uid, int is_pty)
{
    struct pollfd p[2];
    p[0].fd = c; p[0].events = POLLIN;
    p[1].fd = fd; p[1].events = POLLIN;

    char buf[4096];
    char seen[1536];
    size_t sl = 0;
    seen[0] = 0;
    char out[1536];
    size_t ol = 0;
    out[0] = 0;

    for (;;) {
        int r = poll(p, 2, -1);
        if (r < 0) { if (errno == EINTR) continue; break; }

        if (p[0].fd >= 0 && (p[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(c, buf, sizeof(buf));
            if (n <= 0) {
                if (is_pty) {
                    char eof = 4;
                    ssize_t w = write(fd, &eof, 1);
                    (void)w;
                } else {
                    shutdown(fd, SHUT_WR);
                }
                p[0].fd = -1;
            } else {
                if (write_all(fd, buf, (size_t)n) < 0) break;
                if (g_shell_log && sl + 1 < sizeof(seen)) {
                    size_t k = (size_t)n;
                    if (k > sizeof(seen) - 1 - sl) k = sizeof(seen) - 1 - sl;
                    memcpy(seen + sl, buf, k);
                    sl += k;
                    seen[sl] = 0;
                }
            }
        }
        if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write_all(c, buf, (size_t)n) < 0) break;
            if (g_shell_log && ol + 1 < sizeof(out)) {
                size_t k = (size_t)n;
                if (k > sizeof(out) - 1 - ol) k = sizeof(out) - 1 - ol;
                memcpy(out + ol, buf, k);
                ol += k;
                out[ol] = 0;
            }
        }
    }
    if (sl && g_shell_log) {
        sanitize(seen);
        dlog("shell: uid=%d input=\"%s\"", uid, seen);
    }
    if (ol && g_shell_log) {
        sanitize(out);
        dlog("shell: uid=%d output=\"%s\"", uid, out);
    }
}

static void handle_shell(int c, int uid)
{
    char why[256] = {0};
    if (!authorize(uid, "interactive shell", why, sizeof(why))) {
        sendf(c, "D %s\n", why[0] ? why : "denied");
        return;
    }
    if (write_all(c, "O\n", 2) != 2) return;
    dlog("shell: uid=%d open", uid);

    char slave[64];
    const char *tty = env_get("SU_TTY");
    int use_pty = (tty && tty[0] == '1');
    int master = use_pty ? open_pty(slave, sizeof(slave)) : -1;
    int sp[2] = { -1, -1 };
    if (master < 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return;
    }

    pid_t p = fork();
    if (p == 0) {
        close(c);
        become_root();
        apply_client_env();
        set_default_env();
        set_shell_exec_context();

        if (master >= 0) {
            close(master);
            setsid();
            int sl = open(slave, O_RDWR);
            if (sl < 0) _exit(127);
            ioctl(sl, TIOCSCTTY, 0);
            dup2(sl, 0);
            dup2(sl, 1);
            dup2(sl, 2);
            if (sl > 2) close(sl);
        } else {
            close(sp[0]);
            dup2(sp[1], 0);
            dup2(sp[1], 1);
            dup2(sp[1], 2);
            if (sp[1] > 2) close(sp[1]);
        }
        /* 有 tty 才用交互 shell；管道调用（MT 这类）用非交互 sh：
         * 没有提示符/回显，输出是干净的命令结果。 */
        if (master >= 0)
            execl("/system/bin/sh", "sh", "-i", (char *)NULL);
        else
            execl("/system/bin/sh", "sh", (char *)NULL);
        _exit(127);
    }

    if (master >= 0) {
        relay_shell(c, master, uid, 1);
        close(master);
    } else {
        close(sp[1]);
        relay_shell(c, sp[0], uid, 0);
        close(sp[0]);
    }

    int code = wait_status(p);
    dlog("shell: uid=%d exit=%d", uid, code);
}

/* ---------------- 协议处理 ---------------- */

static void send_status(int c)
{
    struct pent e[MAX_POLICY];
    int n = policy_read(e, MAX_POLICY);
    sendf(c, "V %s %d %d %d %d\n", SUV_VERSION, C.manager_uid, C.timeout, 1, n);
}

static void handle_list(int c)
{
    struct pent e[MAX_POLICY];
    int n = policy_read(e, MAX_POLICY);
    char *buf = malloc(64 * 1024);
    if (!buf) { sendf(c, "E oom\n"); return; }
    size_t off = 0;
    for (int i = 0; i < n && off + 32 < 64 * 1024; i++) {
        int k = snprintf(buf + off, 64 * 1024 - off, "%d\t%s\n", e[i].uid,
                         e[i].mode == 1 ? "allow" : "deny");
        if (k > 0) off += (size_t)k;
    }
    sendf(c, "L %zu\n", off);
    if (off) write_all(c, buf, off);
    free(buf);
}

static int handle_answer(const char *rest)
{
    char id[80], token[80], dec[32];
    if (sscanf(rest, "%79s %79s %31s", id, token, dec) != 3) return -1;
    if (!valid_id(id)) return -1;

    char tokfile[400], ansfile[400], tok[80] = {0};
    snprintf(tokfile, sizeof(tokfile), "%s/%s.tok", C.pending, id);
    snprintf(ansfile, sizeof(ansfile), "%s/%s.ans", C.pending, id);

    int tf = open(tokfile, O_RDONLY);
    if (tf < 0) return -1;                 /* 没有这个待处理请求 */
    ssize_t r = read(tf, tok, sizeof(tok) - 1);
    close(tf);
    if (r <= 0) return -1;
    tok[r] = 0;
    while (r > 0 && (tok[r - 1] == '\n' || tok[r - 1] == '\r')) tok[--r] = 0;
    if (strcmp(tok, token) != 0) return -1;

    const char *d = NULL;
    if (!strcmp(dec, "allow") || !strcmp(dec, "allow_once")) d = "allow";
    else if (!strcmp(dec, "allow_always")) d = "allow_always";
    else if (!strcmp(dec, "deny") || !strcmp(dec, "deny_once")) d = "deny";
    else if (!strcmp(dec, "deny_always")) d = "deny_always";
    else if (!strcmp(dec, "timeout")) d = "deny";
    if (!d) return -1;

    int af = open(ansfile, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (af < 0) return (errno == EEXIST) ? 0 : -1;   /* 已回答过：幂等 */
    write_all(af, d, strlen(d));
    close(af);
    return 0;
}

static const char *env_get(const char *key)
{
    if (g_envlen == 0) return NULL;
    size_t klen = strlen(key);
    char *p = g_envblob;
    char *end = g_envblob + g_envlen;
    while (p < end) {
        size_t len = strlen(p);
        if (len == 0) break;
        if (!strncmp(p, key, klen) && p[klen] == '=') return p + klen + 1;
        p += len + 1;
    }
    return NULL;
}

/* 把调用方 argv / 关键环境写进日志，方便排查「某应用说没 root」 */
static void log_su(int uid)
{
    char args[600];
    size_t off = 0;
    args[0] = 0;
    for (char *p = g_argblob; p < g_argblob + g_arglen;) {
        size_t len = strlen(p);
        if (len == 0) break;
        if (off + len + 2 < sizeof(args)) {
            if (off) args[off++] = ' ';
            memcpy(args + off, p, len);
            off += len;
            args[off] = 0;
        }
        p += len + 1;
    }
    for (char *q = args; *q; q++) if (*q == '\n' || *q == '\r') *q = ' ';
    const char *path = env_get("PATH");
    const char *ld = env_get("LD_LIBRARY_PATH");
    dlog("su: uid=%d argv=[%s] PATH=%.200s LD_LIBRARY_PATH=%.120s",
         uid, args, path ? path : "", ld ? ld : "");
}

static void handle_client(int c)
{
    int uid = peer_uid(c);
    if (uid < 0) { close(c); return; }

    struct timeval tv = { 30, 0 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char hdr[MAX_HDR];
    if (read_line(c, hdr, sizeof(hdr)) < 0) { close(c); return; }

    /* 可选 H 头：argv + 关键环境（新客户端都会发） */
    if (hdr[0] == 'H' && hdr[1] == ' ') {
        int argc = 0;
        unsigned long al = 0, el = 0;
        if (sscanf(hdr + 2, "%d %lu %lu", &argc, &al, &el) == 3 &&
            al <= sizeof(g_argblob) && el <= sizeof(g_envblob)) {
            if (read_full(c, g_argblob, al) == (ssize_t)al &&
                read_full(c, g_envblob, el) == (ssize_t)el) {
                g_arglen = al;
                g_envlen = el;
                log_su(uid);
            }
        }
        if (read_line(c, hdr, sizeof(hdr)) < 0) { close(c); return; }
    }

    if (!strcmp(hdr, "V")) {
        dlog("status: uid=%d", uid);
        send_status(c);
    } else if (hdr[0] == 'Q' && (hdr[1] == ' ' || hdr[1] == 0)) {
        long len = (hdr[1] == ' ') ? atol(hdr + 2) : 0;
        if (len <= 0 || len > MAX_CMD) { sendf(c, "E bad length\n"); close(c); return; }
        char *cmd = malloc((size_t)len + 1);
        if (!cmd) { sendf(c, "E oom\n"); close(c); return; }
        if (read_full(c, cmd, (size_t)len) != len) { free(cmd); close(c); return; }
        cmd[len] = 0;
        handle_exec(c, uid, cmd);
        free(cmd);
    } else if (hdr[0] == 'S' && (hdr[1] == 0)) {
        /* 交互 shell 可能长时间没有输入：取消接收超时 */
        struct timeval zero = { 0, 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
        handle_shell(c, uid);
    } else if (hdr[0] == 'L' && (hdr[1] == 0)) {
        if (!is_admin(uid)) sendf(c, "E permission denied\n");
        else handle_list(c);
    } else if (hdr[0] == 'P' && hdr[1] == ' ') {
        int tuid = -1; char mode[16] = {0};
        if (!is_admin(uid) || sscanf(hdr + 2, "%d %15s", &tuid, mode) != 2 || tuid <= 0) {
            sendf(c, "E permission denied\n");
        } else {
            int m = 0;
            if (!strcmp(mode, "allow")) m = 1;
            else if (!strcmp(mode, "deny")) m = 2;
            if (!m || policy_modify(tuid, m) != 0) sendf(c, "E failed\n");
            else {
                dlog("policy: uid=%d -> %s (by %d)", tuid, mode, uid);
                sendf(c, "OK\n");
            }
        }
    } else if (hdr[0] == 'X' && hdr[1] == ' ') {
        int tuid = atoi(hdr + 2);
        if (!is_admin(uid) || tuid <= 0) sendf(c, "E permission denied\n");
        else if (policy_modify(tuid, 0) != 0) sendf(c, "E failed\n");
        else { dlog("policy: uid=%d removed (by %d)", tuid, uid); sendf(c, "OK\n"); }
    } else if (hdr[0] == 'Z' && (hdr[1] == 0)) {
        if (!is_admin(uid)) sendf(c, "E permission denied\n");
        else if (unlink(C.policy) == 0 || errno == ENOENT) { dlog("policy: reset by uid=%d", uid); sendf(c, "OK\n"); }
        else sendf(c, "E failed\n");
    } else if (hdr[0] == 'K' && (hdr[1] == 0)) {
        if (!is_admin(uid)) sendf(c, "E permission denied\n");
        else {
            dlog("daemon: stop by uid=%d", uid);
            sendf(c, "OK\n");
            close(c);
            unlink(C.sock);
            unlink(C.pidfile);
            _exit(0);
        }
    } else if (hdr[0] == 'A' && hdr[1] == ' ') {
        if (handle_answer(hdr + 2) != 0) sendf(c, "E invalid request\n");
        else sendf(c, "OK\n");
    } else {
        sendf(c, "E unknown request\n");
    }
    close(c);
}

/* ---------------- 守护进程 ---------------- */

static void on_term(int sig)
{
    (void)sig;
    unlink(C.sock);
    unlink(C.pidfile);
    _exit(0);
}

static int connect_daemon(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, C.sock, sizeof(sa.sun_path) - 1);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(s); return -1; }
    return s;
}

static int resolve_manager_uid(void)
{
    if (C.manager_uid > 0 || !C.manager[0]) return C.manager_uid;
    FILE *f = fopen(C.packages_list, "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char pkg[256]; int uid = 0;
        if (sscanf(line, "%255s %d", pkg, &uid) == 2 && strcmp(pkg, C.manager) == 0) {
            fclose(f);
            C.manager_uid = uid;
            return uid;
        }
    }
    fclose(f);
    return 0;
}

static int stop_old_daemon(void)
{
    int s = connect_daemon();
    if (s < 0) return 0;           /* 没在跑 */
    close(s);

    FILE *f = fopen(C.pidfile, "r");
    if (f) {
        int pid = 0;
        if (fscanf(f, "%d", &pid) == 1 && pid > 1) {
            kill(pid, SIGTERM);
            for (int i = 0; i < 30; i++) {
                if (kill(pid, 0) != 0) break;
                usleep(100000);
            }
            kill(pid, SIGKILL);
        }
        fclose(f);
    }
    unlink(C.sock);
    unlink(C.pidfile);
    return 1;
}

static int daemonize(void)
{
    pid_t p = fork();
    if (p < 0) return -1;
    if (p > 0) _exit(0);
    setsid();
    p = fork();
    if (p < 0) _exit(1);
    if (p > 0) _exit(0);
    chdir("/");
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) { dup2(fd, 0); dup2(fd, 1); dup2(fd, 2); if (fd > 2) close(fd); }
    return 0;
}

static int run_daemon(void)
{
    /* 已有实例：默认直接成功返回（幂等）；--restart 则替换掉 */
    int probe = connect_daemon();
    if (probe >= 0) {
        close(probe);
        if (!C.restart) {
            fprintf(stderr, "suvd: 已在运行（%s）\n", C.sock);
            return 0;
        }
        stop_old_daemon();
    } else {
        unlink(C.sock);
    }

    mkdir(C.base, 0755);
    mkdir(C.pending, 0700);
    chmod(C.pending, 0700);

    resolve_manager_uid();
    load_bootclasspath();

    if (daemonize() < 0) return 1;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGCHLD, SIG_DFL);

    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) return 1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(C.sock) >= sizeof(sa.sun_path)) return 1;
    strncpy(sa.sun_path, C.sock, sizeof(sa.sun_path) - 1);
    unlink(C.sock);
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        dlog("daemon: bind %s 失败: %s", C.sock, strerror(errno));
        return 1;
    }
    chmod(C.sock, 0666);
    if (listen(ls, 32) != 0) return 1;

    {
        int pf = open(C.pidfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (pf >= 0) {
            char b[32];
            int n = snprintf(b, sizeof(b), "%d\n", (int)getpid());
            write_all(pf, b, (size_t)n);
            close(pf);
        }
    }

    dlog("daemon: start pid=%d base=%s manager=%s uid=%d timeout=%d",
         (int)getpid(), C.base, C.manager[0] ? C.manager : "(none)", C.manager_uid, C.timeout);

    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            usleep(10000);
            continue;
        }
        pid_t p = fork();
        if (p == 0) {
            close(ls);
            handle_client(c);
            _exit(0);
        }
        close(c);
        while (waitpid(-1, NULL, WNOHANG) > 0) { }
    }
}

/* ---------------- 客户端 ---------------- */

static int connect_client(void)
{
    int s = connect_daemon();
    if (s < 0) {
        fprintf(stderr, "su: 守护进程没有运行。请打开「老机 Root」点「一键获取 Root」。\n");
        return -1;
    }
    return s;
}

/* H <argc> <argblen> <envblen>\n + argv blob + env blob（均为 NUL 分隔） */
static void send_hello(int s)
{
    static const char *keys[] = {
        "PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "HOME", "TMPDIR", "SHELL",
        "USER", "LOGNAME", "PWD", "LANG", "TERM", "ANDROID_ROOT",
        "ANDROID_DATA", "ANDROID_STORAGE", "EXTERNAL_STORAGE", "BOOTCLASSPATH",
    };

    char args[2048];
    size_t al = 0;
    for (int i = 0; i < g_argc && g_argv; i++) {
        size_t l = strlen(g_argv[i]);
        if (al + l + 1 >= sizeof(args)) break;
        memcpy(args + al, g_argv[i], l);
        al += l;
        args[al++] = 0;
    }

    char env[8192];
    size_t el = 0;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *v = getenv(keys[i]);
        if (!v) continue;
        size_t kl = strlen(keys[i]);
        size_t vl = strlen(v);
        if (el + kl + vl + 2 >= sizeof(env)) break;
        memcpy(env + el, keys[i], kl);
        el += kl;
        env[el++] = '=';
        memcpy(env + el, v, vl);
        el += vl;
        env[el++] = 0;
    }
    {
        const char *t = isatty(0) ? "SU_TTY=1" : "SU_TTY=0";
        size_t tl = strlen(t);
        if (el + tl + 1 < sizeof(env)) {
            memcpy(env + el, t, tl);
            el += tl;
            env[el++] = 0;
        }
    }

    sendf(s, "H %d %zu %zu\n", g_argc, al, el);
    if (al) write_all(s, args, al);
    if (el) write_all(s, env, el);
}

/* 客户端：
 * 读全部输出，在内存里找尾部 sentinel（"\n__SUVX_<nonce>_<code>__\n"）。
 * 命令输出上限 16MB；超出部分会被截断，退出码仍然有效。
 */
static int client_exec(const char *cmd)
{
    int s = connect_client();
    if (s < 0) return 1;

    size_t len = strlen(cmd);
    if (len > MAX_CMD) { fprintf(stderr, "su: 命令太长\n"); close(s); return 1; }
    send_hello(s);
    sendf(s, "Q %zu\n", len);
    if (write_all(s, cmd, len) != (ssize_t)len) { close(s); return 1; }

    char hdr[MAX_HDR];
    if (read_line(s, hdr, sizeof(hdr)) < 0) {
        fprintf(stderr, "su: 守护进程没有回应\n");
        close(s);
        return 1;
    }
    if (hdr[0] == 'D' || hdr[0] == 'E') {
        fprintf(stderr, "su: %s\n", hdr[2] ? hdr + 2 : "拒绝");
        close(s);
        return 1;
    }
    if (hdr[0] != 'O') {
        fprintf(stderr, "su: 应答异常（%s）\n", hdr);
        close(s);
        return 1;
    }

    /* 读全部输出，在内存里找尾部 sentinel。命令输出上限 16MB。 */
    size_t cap = 65536, used = 0;
    char *all = malloc(cap);
    if (!all) { close(s); return 1; }
    for (;;) {
        if (used == cap) {
            if (cap >= 16 * 1024 * 1024) break;
            cap *= 2;
            char *nb = realloc(all, cap);
            if (!nb) break;
            all = nb;
        }
        ssize_t n = read(s, all + used, cap - used);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        used += (size_t)n;
    }
    close(s);

    int code = 1;
    size_t start = used;
    if (used >= 4) {
        for (size_t i = used; i > 0; i--) {
            if (all[i - 1] == '\n' && used - i > 10 &&
                !memcmp(all + i, "__SUVX_", 7)) {
                start = i - 1;
                const char *p = all + i + 7;
                const char *us = strchr(p, '_');   /* nonce 与退出码之间的 '_' */
                if (us) code = atoi(us + 1);
                break;
            }
        }
    }
    if (start > 0) write_all(1, all, start);
    free(all);
    return code;
}

static int client_shell(void)
{
    int s = connect_client();
    if (s < 0) return 1;
    send_hello(s);
    if (write_all(s, "S\n", 2) != 2) { close(s); return 1; }

    char hdr[MAX_HDR];
    if (read_line(s, hdr, sizeof(hdr)) < 0) { close(s); return 1; }
    if (hdr[0] == 'D' || hdr[0] == 'E') {
        fprintf(stderr, "su: %s\n", hdr[2] ? hdr + 2 : "拒绝");
        close(s);
        return 1;
    }
    if (hdr[0] != 'O') { close(s); return 1; }

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
            if (write_all(s, buf, (size_t)n) < 0) break;
        }
        if (pfd[1].revents & (POLLIN | POLLHUP)) {
            ssize_t n = read(s, buf, sizeof(buf));
            if (n <= 0) break;
            write_all(1, buf, (size_t)n);
        }
    }
    close(s);
    return 0;
}

/* ---------------- 入口 ---------------- */

static const char *base_name(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static const char *join_args(int argc, char **argv, int from)
{
    static char buf[MAX_CMD];
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

static void usage(void)
{
    printf("用法:\n");
    printf("  su [-c 命令] [uid] [-s SHELL]     以 root 执行（默认 uid 0）\n");
    printf("  su                                 交互式 root shell\n");
    printf("  su -v | -V | -h                    版本 / 帮助\n");
    printf("  suvd -d [选项]                     启动守护进程\n");
    printf("     --base DIR          运行目录（默认 /data/local/tmp/.su）\n");
    printf("     --manager PKG       管理 App 包名（弹窗由它显示）\n");
    printf("     --manager-uid UID   管理 App uid（不给则从 packages.list 解析）\n");
    printf("     --timeout SEC       弹窗等待秒数（默认 %d）\n", DEF_TIMEOUT);
    printf("     --allow-uid UID     直接放行某 uid，可重复（调试用）\n");
    printf("     --restart           替换已在运行的守护进程\n");
    printf("     --debug-shell       记录交互 shell 的输入输出（排查兼容性）\n");
    printf("  suvd -t                             触发 socket(30) → request_module\n");
    printf("  suvd --status                       查询守护进程状态\n");
}

static int trigger_module(void)
{
    int s = socket(30, SOCK_STREAM, 0);
    printf("socket(30)=%d errno=%d\n", s, errno);
    if (s >= 0) close(s);
    return 0;
}

static void init_cfg(void)
{
    memset(&C, 0, sizeof(C));
    snprintf(C.base, sizeof(C.base), "/data/local/tmp/.su");
    snprintf(C.packages_list, sizeof(C.packages_list), "/data/system/packages.list");
    C.timeout = DEF_TIMEOUT;
}

static void fill_paths(void)
{
    snprintf(C.sock, sizeof(C.sock), "%s/suvd.sock", C.base);
    snprintf(C.policy, sizeof(C.policy), "%s/policy.tsv", C.base);
    snprintf(C.log, sizeof(C.log), "%s/suvd.log", C.base);
    snprintf(C.lock, sizeof(C.lock), "%s/policy.lock", C.base);
    snprintf(C.pending, sizeof(C.pending), "%s/pending", C.base);
    snprintf(C.pidfile, sizeof(C.pidfile), "%s/suvd.pid", C.base);
}

static int su_main(int argc, char **argv)
{
    const char *cmd = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-v") || !strcmp(a, "--version")) { printf("%s\n", COMPAT_VERSION); return 0; }
        if (!strcmp(a, "-V")) { printf("%s %s (%s)\n", SUV_TAG, SUV_VERSION, COMPAT_VERSION); return 0; }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        if (!strcmp(a, "-c") || !strcmp(a, "--command")) {
            if (i + 1 >= argc) { fprintf(stderr, "su: -c 需要参数\n"); return 1; }
            cmd = join_args(argc, argv, i + 1);
            break;
        }
        if (!strcmp(a, "-s") || !strcmp(a, "--shell")) { i++; continue; }
        if (!strcmp(a, "-p") || !strcmp(a, "--preserve-environment") ||
            !strcmp(a, "-l") || !strcmp(a, "--login") ||
            !strcmp(a, "-m") || !strcmp(a, "-M") || !strcmp(a, "--mount-master") ||
            !strcmp(a, "--context")) { continue; }
        if (!strcmp(a, "--user") || !strcmp(a, "-u")) { i++; continue; }
        if (!strcmp(a, "0") || !strcmp(a, "--uid") || !strcmp(a, "root")) continue;
        if (a[0] == '-') continue;
        cmd = join_args(argc, argv, i);
        break;
    }

    if (cmd && cmd[0]) return client_exec(cmd);
    return client_shell();
}

int main(int argc, char **argv)
{
    init_cfg();
    fill_paths();
    g_argc = argc;
    g_argv = argv;

    const char *prog = base_name(argv[0]);
    if (!strcmp(prog, "su")) return su_main(argc, argv);

    if (argc >= 2) {
        const char *a = argv[1];
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", SUV_TAG, SUV_VERSION);
            return 0;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        if (!strcmp(a, "-t")) return trigger_module();
        if (!strcmp(a, "--status")) {
            int s = connect_daemon();
            if (s < 0) { printf("not running\n"); return 1; }
            sendf(s, "V\n");
            char hdr[MAX_HDR];
            if (read_line(s, hdr, sizeof(hdr)) >= 0) printf("%s\n", hdr);
            close(s);
            return 0;
        }
        if (!strcmp(a, "-d")) {
            for (int i = 2; i < argc; i++) {
                const char *o = argv[i];
                if (!strcmp(o, "--base") && i + 1 < argc) {
                    snprintf(C.base, sizeof(C.base), "%s", argv[++i]);
                    fill_paths();
                } else if (!strcmp(o, "--manager") && i + 1 < argc) {
                    snprintf(C.manager, sizeof(C.manager), "%s", argv[++i]);
                } else if (!strcmp(o, "--manager-uid") && i + 1 < argc) {
                    C.manager_uid = atoi(argv[++i]);
                } else if (!strcmp(o, "--timeout") && i + 1 < argc) {
                    C.timeout = atoi(argv[++i]);
                    if (C.timeout < 5) C.timeout = 5;
                    if (C.timeout > 600) C.timeout = 600;
                } else if (!strcmp(o, "--allow-uid") && i + 1 < argc) {
                    if (C.nallow < MAX_ALLOW_UID) C.allow_uid[C.nallow++] = atoi(argv[++i]);
                } else if (!strcmp(o, "--restart")) {
                    C.restart = 1;
                } else if (!strcmp(o, "--debug-shell")) {
                    g_shell_log = 1;
                } else if (!strcmp(o, "--verbose")) {
                    g_verbose = 1;
                } else {
                    fprintf(stderr, "suvd: 未知选项 %s\n", o);
                    return 1;
                }
            }
            return run_daemon();
        }
    }
    usage();
    return 1;
}
