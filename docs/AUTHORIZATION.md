# 授权层（suvd）

`src/suvd.c` 一个二进制干两件事：

- `suvd -d ...`：root 守护进程；
- `su ...`：客户端（`/sbin/su` 是指向同一个二进制的链接，按 `argv[0]` 区分）。

## 守护进程参数

```
suvd -d --base /data/local/tmp/.su \
       --manager com.oldroot.manager \
       --manager-uid 10126 \
       --timeout 60 [--restart] [--debug-shell] [--allow-uid 2000]
```

| 参数 | 说明 |
|---|---|
| `--base` | 运行目录（tmpfs），默认 `/data/local/tmp/.su` |
| `--manager` | 管理 App 包名，弹窗由它显示 |
| `--manager-uid` | 管理 App uid：本人请求直接放行，也是管理员命令的身份 |
| `--timeout` | 弹窗等待秒数，默认 60 |
| `--restart` | 替换已在运行的守护进程 |
| `--allow-uid` | 免询问 uid，可重复（PC 调试用，默认不给） |
| `--debug-shell` | 把交互 shell 的输入输出写日志（排查兼容性） |

## 客户端协议

socket：`/data/local/tmp/.su/suvd.sock`，`0666`，对端身份用 `SO_PEERCRED` 读取。

每行一个头，可选的 `H` 头用来带 argv 和环境：

| 请求 | 回复 |
|---|---|
| `H <argc> <argblen> <envblen>\n` + blob | 无（只写日志） |
| `V\n` | `V <ver> <manager_uid> <timeout> <default> <entries>\n` |
| `Q <len>\n` + cmd | `O\n` + 输出 + `\n__SUVX_<nonce>_<code>__\n`；拒绝时 `D <原因>\n` |
| `S\n` | `O\n` + shell；拒绝时 `D <原因>\n` |
| `L\n` | `L <len>\n` + `uid\tmode\n`（管理员） |
| `P <uid> <allow\|deny>\n` | `OK\n`（管理员） |
| `X <uid>\n` | `OK\n`（管理员） |
| `Z\n` | `OK\n`（管理员，清空） |
| `K\n` | `OK\n`（管理员，停止守护进程） |
| `A <id> <token> <decision>\n` | `OK\n`（弹窗回答，凭 token） |

`decision` 取值：`allow` / `allow_always` / `deny` / `deny_always` / `timeout`。

### 为什么有 H 头

`apply_client_env()` 把调用方的 `PATH`、`LD_LIBRARY_PATH`、`LD_PRELOAD`、
`HOME`、`TMPDIR`、`SHELL`、`ANDROID_*` 等透传给 root 进程。真实 `su` 也保留
调用方环境；MT 管理器、冰箱这类应用会依赖自己的环境变量，丢掉它们会表现为
“授权了但没 root”。

`SU_TTY=1/0` 也在这个头里，用来决定 shell 形态。

## 策略

`policy.tsv`（`0644`）每行 `uid<TAB>allow|deny`。读取时不缓存，改完立即生效。
弹窗勾选“记住”才会写入；`P`/`X`/`Z` 也可由管理 App 修改。

## 弹窗流程

1. 未命中策略 → 生成 `id` + 16 字节随机 `token`，写入 `pending/<id>.tok`；
2. fork 子进程：
   - `/proc/self/attr/exec` 写入 `u:r:shell:s0`；
   - `setgid(2000); setuid(2000)`；
   - `exec /system/bin/am start ... -n <manager>/.PromptActivity --es id ... --es token ...`；
3. 管理 App 显示弹窗；用户点允许/拒绝后，App 通过 `A <id> <token> <decision>`
   连回守护进程；
4. 等待子进程轮询 `pending/<id>.ans`，超时按拒绝；
5. 写入策略（仅“永久”），清理 `pending`，继续执行或返回 `D`。

用 `am` 而不是让 App 自己弹，是因为 MIUI 会拦截后台应用的 Activity 启动
（`MIUI Permission Denied Activity`）；shell 发起的启动放行。为让 `am`
能连上 service_manager，子进程必须切到 `u:r:shell:s0` 并降权到 2000。

安全边界：`id` + 128-bit `token` 只通过显式 Intent 交给管理 App；别的应用既收不到
也猜不到。`A` 命令不检查 uid，只校验 token。

## shell 语义

`handle_shell()` 根据 `SU_TTY` 分两条路：

- **管道**（`SU_TTY=0`，MT / 冰箱 / 大多数 root 工具）：
  socketpair 直连，`/system/bin/sh` **不带 `-i`**。没有提示符、没有回显、
  没有 `can't find tty fd` 警告，输出就是命令结果；
- **终端**（`SU_TTY=1`，人敲 `su`）：
  分配 pty（`posix_openpt` + `TIOCSCTTY`），`sh -i`，回显、提示符、Ctrl-C 正常。

`sh` 和 `su -c` 都以 **uid 0 + `u:r:shell:s0`** 执行：

- uid 0 让文件操作不受 DAC 限制（全 capability 来自内核 payload）；
- shell 域才能 `find` 到 `activity` / `package` 等服务，`pm`、`am`、`dumpsys` 可用。
  kernel 域会报 `Can't connect to activity manager`。

`exec` 用 `/system/bin/sh -c`，stdout/stderr 直接写到 socket，退出码放在
随机 nonce 的尾部标记里，客户端据此返回真实退出码。

## 日志

`/data/local/tmp/.su/suvd.log`（`0644`，超过 512KB 轮转 `.1`）：

```
su: uid=10131 argv=[su] PATH=... LD_LIBRARY_PATH=...
exec: uid=10131 cmd="pm disable-user --user 0 com.example"
exec: uid=10131 exit=0
prompt: uid=10132 等待授权 id=... cmd="..."
prompt: uid=10132 -> allow (always)
```

`--debug-shell` 额外记录 `shell: uid=... input="..."` / `output="..."`，
用于定位某个应用为什么不认 root。

## 排错顺序

1. `suvd --status` 看守护进程是否在、manager uid 对不对；
2. `su -v` / `su -c id` 看基础链路；
3. 应用仍说没 root：开 `--debug-shell`，复现一次，看它的 shell 输入输出；
4. 确认 `/sbin` 是 `0755`、`/sbin/su` 链接存在；
5. 确认 root 命令的 `id` 里 `context=u:r:shell:s0`（否则 `pm`/`am` 会失败）。
