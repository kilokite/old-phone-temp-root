# old-phone-temp-root

老 Android 机的临时 root + 授权管理：一个能装在手机上的 App（**老机 Root**），
点一次「一键获取 Root」完成 CVE-2019-2215 提权，然后像成熟 root 管理器一样
给其他应用弹窗授权。不刷机、不写分区，**重启即失效**。

参考机型验证：Xiaomi Mi 5 / Android 6.0.1 / kernel 3.18.20 / arm64。

```
             ┌──────────────────── 手机端 App「老机 Root」 ────────────────────┐
 tap 一键     │ probe26 → binder UAF → selinux_enforcing=0, modprobe_path=wb.sh │
             │        └─ socket(30) → request_module → 内核以 root 执行 wb.sh   │
             └──────────────────────────────────────────────────────────────────┘
                                          │
                        wb.sh（root）      ▼
        ┌──────────────────────────────────────────────────────────────┐
        │ mount tmpfs /data/local/tmp/.su                              │
        │ 拷入 suvd，/sbin/su → suvd（并 chmod 0755 /sbin）             │
        │ suvd -d --manager com.oldroot.manager --manager-uid <uid>    │
        └──────────────────────────────────────────────────────────────┘
                                          │ unix socket
   第三方应用 ── su [-c 命令] ──► /sbin/su（suvd 客户端） ──► 授权 ──► sh -c（uid 0，全 capability）
                                                          └─ am start 弹窗（shell 域）
```

## 手机端使用（推荐）

### 构建 / 安装

```bash
python build.py                 # 交叉编译 probe26 / trig_sock / suvd
python tools/build_apk.py       # 打 APK（不用 Gradle）
adb install -r dist/oldroot-manager.apk
```

也可以直接把 `dist/oldroot-manager.apk` 传到手机，用文件管理器安装。
`minSdk 21 / targetSdk 23 / arm64-v8a`。

### 一键获取 Root

打开「老机 Root」→「一键获取 Root」→「开始」。几秒后状态变为
**已获取 Root · SELinux Permissive**，同时：

- `/data/local/tmp/.su/suvd` 授权守护进程启动；
- `/sbin/su` 指向 suvd，`/sbin` 权限放开到 `0755`；
- 授权记录在 `/data/local/tmp/.su/policy.tsv`，日志在 `suvd.log`。

重启后全部恢复原样，重新点一次即可。

## 其他应用怎么拿 root

应用不需要任何改造，照常调用 `su`：

```java
Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", "id"});
// 或
Process p = Runtime.getRuntime().exec("su -c \"pm disable-user --user 0 com.example\"");
```

第一次调用会弹出授权框（应用名 / uid / 命令 / 倒计时）：

- **允许**：以 uid 0、全 capability 执行；
- **拒绝**：返回失败并给出原因；
- 勾选「记住我的选择」后写入策略，以后不再询问；
- 超时（默认 60 秒）按拒绝处理。

`su` 的兼容行为：

| 调用 | 行为 |
|---|---|
| `su -c "cmd"` | 非交互执行，stdout/stderr 原样返回，退出码透传 |
| `su`（管道） | 干净的非交互 shell：无提示符、无回显 |
| `su`（终端 tty） | pty + `sh -i`，正常交互 |
| `su -v` / `--version` | `2.82:SUPERSU`（老应用识别用） |
| `su 0 -c ...`、`-s SHELL`、`-m/-M` | 兼容解析 |

授权后执行的是 `u:r:shell:s0`、uid 0、全 capability 的进程，所以 `pm`、`am`、
`dumpsys`、`settings` 这些依赖系统服务的命令也能用，文件操作也不受 DAC 限制。

已实测：**MT 管理器**（`/data` 全量目录、root 终端）、**冰箱 Ice Box 3.25.1**
（`pm disable-user` / `am force-stop` 冻结应用）。

## 兼容性：为什么很多 su 在旧机上“看着授权了但没 root”

这三处是实测踩出来的，都在本实现里处理了：

1. **`/sbin` 是 `0750`**。只把 `su` 放进 `/sbin` 没用，应用连目录都进不去。
   `wb.sh` 会 `mount -o remount,rw /` 后 `chmod 0755 /sbin` 再放链接。
2. **MIUI 拦截后台应用弹 Activity**（日志 `MIUI Permission Denied Activity`）。
   授权框由守护进程 **降权到 uid 2000、exec 域切到 `u:r:shell:s0` 后调用 `am start`**
   拉起，等同于 `adb shell am start`，不受该限制。
3. **shell 形态必须匹配调用方**。MT / 冰箱这类应用用管道调 `su`，期待干净的
   非交互输出；强制 `sh -i` 或 pty 会多出提示符/回显/`can't find tty fd` 警告，
   它们的解析器会判定 root 失败。现在按 `SU_TTY` 自动选择：
   - 管道 → 非交互 `sh`，无提示符、无回显；
   - 终端 → pty + `sh -i`。

   同时把调用方的 `PATH` / `LD_LIBRARY_PATH` / `TMPDIR` 等环境透传给 root 进程，
   否则依赖自身环境的命令（MT 的 term/bin、冰箱的 pm）会失败。
4. **root 进程必须能访问 service_manager**。kernel 域里的 `pm`/`am` 会报
   `Can't connect to ...`，所以 root 命令统一在 `u:r:shell:s0` 下执行。

## PC 部署（调试用）

不想装 App 时，可以走 adb：

```bash
python deploy.py
python deploy.py --serial <serial>
```

推送 + 跑利用 + 触发 payload + 启动守护进程，并默认把 `adb shell`（uid 2000）
加入免询问名单。验证：

```bash
adb shell su -c id
adb shell su -c 'pm list packages | head'
```

## 目录结构

```
old-phone-temp-root/
├── app/                      # Android 管理 App（Java，无 AndroidX）
│   ├── AndroidManifest.xml
│   ├── res/                  # 图标、字符串
│   └── src/com/oldroot/manager/
│       ├── MainActivity.java     # 状态 / 一键 root / 授权列表 / 高级命令
│       ├── PromptActivity.java   # 授权弹窗（token 回答）
│       ├── RootInstaller.java    # 解包、跑 probe26、触发、验证
│       ├── RootManager.java      # suvd 客户端（LocalSocket）
│       └── LogActivity.java      # 日志查看
├── src/
│   ├── probe26.c             # CVE-2019-2215 利用（readv 自覆写链，一次链双写）
│   ├── trig_sock.c           # socket(30) 触发 request_module
│   └── suvd.c                # 授权守护进程 + su 客户端（同一二进制）
├── payload/wb.sh             # 内核以 root 执行的脚本
├── tools/
│   ├── build_apk.py          # aapt2 + javac + d8 + apksigner，无需 Gradle
│   ├── build_testapp.py      # 第三方应用测试包（只调 su -c）
│   ├── tap.sh / uiauto/      # MIUI 禁用 adb input 时的无 root UI 驱动
│   └── ...
├── testapp/                  # 「Root 测试」源码
├── docs/
│   ├── HOW-IT-WORKS.md       # 漏洞、偏移、利用链
│   ├── AUTHORIZATION.md      # suvd 协议、策略、弹窗与 shell 语义
│   └── TROUBLESHOOTING.md
├── build.py                  # NDK 交叉编译
├── deploy.py                 # PC 部署
└── cleanup.py                # 停止守护进程、清理
```

## 限制

- 只在本 boot 有效：重启后 SELinux、`modprobe_path`、tmpfs、daemon 全部复原。
- 只支持 arm64 + 未打 2019-10 补丁的 3.18 内核（参考机型）。移植见
  [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) 与 `build.py --define`。
- 运行后 SELinux 是 Permissive，直到重启。
- `probe26` 依赖堆布局；`readv` 返回值不等于 69760 时重启再试，不要用它判断写入是否生效。
- 内核 `panic_on_oops=1` 时，链错位会直接重启。

## 关键地址

来自参考机 `System.map`（`_text = 0xffffffc000080000`，KASLR 关闭）：

| 符号 | 地址 |
|---|---|
| `selinux_enforcing` | `0xffffffc002283174` |
| `modprobe_path` | `0xffffffc001e37ce0` |

换机型用 `python build.py --define A_SELINUX_ENFORCING=0x... --define A_MODPROBE_PATH=0x...`。

## 参考

- CVE-2019-2215 原始报告：Google Project Zero issue 1942
- 触发原语与工程实现：`FDLAlfrid/odin-od105-devkit`
- 4.4 几何：`grant-h/qu1ckr00t`、`kangtastic/cve-2019-2215`

## 许可

MIT，见 [LICENSE](LICENSE)。`src/probe26.c` 源自上述公开工程（MIT）。
