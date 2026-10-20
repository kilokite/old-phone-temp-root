# 原理

## 1. 漏洞：CVE-2019-2215

`binder_poll()` 会把 `binder_thread` 里的等待队列挂到 epoll 上：

```c
if (wait_for_proc_work)
        poll_wait(filp, &proc->wait, wait);
else
        poll_wait(filp, &thread->wait, wait);
```

`BINDER_THREAD_EXIT` 会直接释放 `binder_thread`，但 epoll 里仍然留着指向
`thread->wait` 的 wait queue 项。之后 `EPOLL_CTL_DEL` 走
`remove_wait_queue()`，对一个已释放对象做 `list_del_init()`。

## 2. 3.18 的额外条件：线程必须"忙"

3.18 的实现是：

```c
wait_for_proc_work = thread->transaction_stack == NULL &&
                     list_empty(&thread->todo) &&
                     thread->return_error == BR_OK;
```

空闲线程会挂到 `proc->wait`，**不会**触发 UAF。所以要先发一个
`BC_TRANSACTION`（target.handle = 0，即 context manager），让
`thread->transaction_stack` 非空；只要 `todo` 仍为空，`binder_poll()` 就会走
`else` 分支，把 `&thread->wait` 挂进 epoll。

`probe26` 在 `BINDER_WRITE_READ` 之后检查：

```
write_consumed == 68 && read_consumed == 8 &&
rb[0] == BR_NOOP && rb[1] == BR_TRANSACTION_COMPLETE
```

`read_consumed == 8` 说明回复还没到（回复一旦入队，`todo` 非空，
`binder_poll` 会直接返回 `POLLIN`、不挂队列）。

## 3. 对象布局与 0x48

3.18 的 `struct binder_thread`：

```c
struct binder_thread {
        struct binder_proc *proc;                      /* 0x00 */
        struct rb_node rb_node;                        /* 0x08 (24) */
        int pid, looper;                               /* 0x20 / 0x24 */
        struct binder_transaction *transaction_stack;  /* 0x28 */
        struct list_head todo;                         /* 0x30 (16) */
        uint32_t return_error, return_error2;          /* 0x40 / 0x44 */
        wait_queue_head_t wait;                        /* 0x48  <-- */
        struct binder_stats stats;                     /* 0x60 */
};                                                        /* 0x118 = 280 */
```

280 字节落在 **kmalloc-512**。`wait` 在 **0x48**，不是 4.4 PoC 里的 0xA0。

## 4. 用 readv 的 kiovec 数组回收

`readv(fd, iov, 25)` 在 import 时会 `kmalloc` 一份内核数组（25×16 = 400B，
同样落在 kmalloc-512）。25 > 8 是为了绕开栈上的快速路径，保证走 kmalloc。

在 `THREAD_EXIT` 之后立刻发起阻塞的 `readv`，该数组按 LIFO 抢到刚释放的
`binder_thread` 槽位，于是 **内核数组地址 = X**（旧 `binder_thread`）。

## 5. DEL 把数组改成一个可推进的链

`EPOLL_CTL_DEL` → `ep_unregister_pollwait()` → `remove_wait_queue(&X->wait)`：

- `q->lock` 在 X+0x48。ARM64 3.18 是 ticket spinlock：
  `spin_lock` 让 `next++`，`spin_unlock` 让 `owner++`，各加 `0x10000`，
  合计 `X+0x48 = 0x00010001`。因为 iov[4] 的初值是 0，低 32 位正好是
  `iov[4].iov_len = 65537`。
- `list_del_init(&pwq->wait.task_list)` 把 `q->task_list` 写回自身：
  `X+0x50 = X+0x58 = X+0x50`，即 `iov[5] = {X+0x50, X+0x50}`（长度极大）。

## 6. 单次 write 推进 iov，落到两个静态地址

`readv` 阻塞后，另起子进程往 pipe 里**一次连续写入** `69632 + payload` 字节。
`copy_page_to_iter_iovec()` 每轮会重新读取 `iov->iov_len`，于是：

1. 前 3871 字节被 iov[0] 吃掉；
2. iov[4] 的 65537 字节再吃掉 65537；
3. 此时 iov[5].iov_base = X+0x50，下一块 4096B 的拷贝把 224 字节写进
   `X+0x50..X+0x12F`——这段**仍在我们自己的 400B 数组内**，内容是我们喂的伪造块：

   | 偏移 | 含义 |
   |---|---|
   | +8  | `iov[5].iov_len := 224`（必须等于本次拷贝字节数） |
   | +16 | `iov[6].iov_base := &selinux_enforcing` |
   | +24 | `iov[6].iov_len := 4` |
   | +32 | `iov[7].iov_base := &modprobe_path` |
   | +40 | `iov[7].iov_len := 24` |
   | +48 | 其余 iov 清零（零长段会被跳过） |

4. 224 字节拷完时 `skip == iov[5].iov_len`，`iov++` 前进到 iov[6]，
   后续 payload 依次 `__copy_to_user` 到两个目标地址。

`access_ok` 只在 `import_iovec` 进口时对用户态原值检查一次；运行期把
`iov_base` 改成内核地址不会再检查，这是整个原语成立的前提。

## 7. 收尾

`modprobe_path` 指向 `/data/local/tmp/wb.sh`。用
`socket(30, SOCK_STREAM, 0)` 请求一个未注册协议族：

```
__sock_create -> request_module("net-pf-30") -> call_usermodehelper()
```

内核以 uid 0 / `u:r:kernel:s0` 执行 payload。`wb.sh` 会：

1. 在 `/data/local/tmp/.su` 挂一个 tmpfs（`/data` 是 nosuid，setuid 只在
   tmpfs 上有效）；
2. 把 `su` 拷进去并 `chmod 4755`；
3. 起 `rootshell -d`，在 `/data/local/tmp/.rs` 上提供一个 root shell。

## 8. 硬约束

- **必须单次连续 write**：pipe_read 有 syscall-merging 早退路径，
  分多次写会让块边界错位。
- **读端块粒度 4096**：`SEG0_LEN + 65537 + 224` 要对齐到 4096 边界，
  否则会越过数组打进相邻 slab 对象。
- **kmalloc-512 纪律**：临界窗口内不能有额外的 kmalloc-512 分配，
  否则 steal 会抢错槽。清场的 40 个常驻 ballast 就是为此。
- `panic_on_oops=1`：任何一步错位都是直接重启，不会给你看现场的机会。

## 9. 地址是怎么来的

`Image.vmlinux` 解压后 `_text = 0xffffffc000080000`，KASLR 关闭（崩溃日志里的
PC 全部落在 `0xffffffc0...` 且多次重启不变）。两个目标地址直接取
`System.map`：

```
ffffffc001e37ce0 D modprobe_path
ffffffc002283174 B selinux_enforcing
```

换内核时用同样的方法重新取，不需要改结构体逻辑。
