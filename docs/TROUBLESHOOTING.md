# 排错

## `adb: more than one device/emulator`

机器上还有别的设备或模拟器。用序列号：

```bash
adb -s <serial> shell ...
python deploy.py --serial <serial>
```

## `probe26` 的 `readv` 返回值不是 69760

说明链没有按设计推进（steal 抢错槽、块边界错位、或有别的 kmalloc-512 分配插队）。

- 直接重跑一次；仍不行就重启后再跑。
- 不要用这个返回值判断“写没写成功”——以 `getenforce` 为准。
- 日志在 `/data/local/tmp/probe26.log` 或 App 的 `files/root/probe26.log`。

## `getenforce` 仍然是 `Enforcing`

`selinux_enforcing` 的写入没生效，通常同上：链没命中。重跑或重启重试。

## `trig_sock` 返回 `errno=97`（EAFNOSUPPORT）

正常：`socket(30)` 必然失败，目的只是让内核走到 `request_module("net-pf-30")`。
判断成功与否看 `modprobe_path` 是否被改写、守护进程是否起来。

## payload 没执行

- `modprobe_path` 是否指向 `wb.sh`（App 流程是
  `/data/user/0/com.oldroot.manager/files/root/wb.sh`；PC 流程是
  `/data/local/tmp/wb.sh`）。
- `wb.sh` 必须有可执行位，第一行是 `#!/system/bin/sh`。
- usermodehelper 的环境不可靠，脚本里全部用绝对路径（已处理）。
- 看 `/data/local/tmp/.payload_ran` 的时间戳有没有更新。

## App 一键获取 Root 失败

- 弹窗里会直接给出 `probe26` 的尾部输出，先看 `readv=.../...` 和 `result=`。
- 失败多半是堆布局问题：重启手机再点一次。
- `panic_on_oops=1` 的机器可能直接重启，属预期风险。
- 路径太长？App 的 `files/root/wb.sh` 必须在 200 字节以内。

## 授权弹窗不出现

- 状态页必须显示「已获取 Root」且守护进程在跑。
- 管理 App 不能是被「强行停止」的状态；`am start` 可以拉起已停止的应用，
  但部分 ROM 的“自启动管理”会拦，给「老机 Root」开自启动。
- 看 `/data/local/tmp/.su/suvd.log` 里有没有 `prompt: ... am start 失败`。
  失败常见原因：管理 App 被卸载/包名不对。

## 应用已授权，但仍然显示“没有 root”

这是兼容性问题，不是授权失败。按顺序查：

1. **它是不是在用管道跑 `su`？** 我们要给非交互 shell（无提示符、无回显）。
   开 `--debug-shell` 重启守护进程，复现一次，看
   `shell: uid=... input=... / output=...`。
2. **它依赖自己的环境变量？** `PATH` / `LD_LIBRARY_PATH` / `TMPDIR` 已经透传；
   如果还有别的变量，把它加到 `send_hello()` 的 keys 里。
3. **root 命令是不是在 kernel 域？** `su -c 'id'` 应该显示
   `context=u:r:shell:s0`。kernel 域里 `pm`/`am` 会报
   `Can't connect to activity manager`。
4. **它是不是只认固定路径？** 有些应用会扫 `/system/xbin/su`、`/system/bin/su`。
   我们只提供 `/sbin/su`（不写 `/system`，避免 verity）。确认应用是否支持 PATH。

已实测：

- **MT 管理器**：探针是 `echo Started` → `id -u` → `echo 'MT - End of command'`，
  必须是非交互 shell；授权后 `/data` 可全量浏览。
- **冰箱 Ice Box 3.25.1**：通过 `pm disable-user` / `am force-stop` 冻结，
  需要 root 进程在 shell 域（能访问 package service）。

## `su: not found` / 应用找不到 su

- `/sbin/su` 是否存在：`ls -l /sbin/su`。
- `/sbin` 是否是 `0755`：`ls -ld /sbin`。很多 ROM 默认 `0750 root:root`，
  应用连目录都进不去，必须在 `mount -o remount,rw /` 后 `chmod 0755`。
- 应用的 `PATH` 一般包含 `/sbin`；不包含的话让它用绝对路径
  `/data/local/tmp/.su/su`。

## APK 装不上

- `INSTALL_CANCELED_BY_USER`（MIUI）：`adb install` 会被安装器二次确认拦，
  用文件管理器点安装，或在开发者选项里打开“USB 安装”。
- `INSTALL_FAILED_OLDER_SDK` / “解析软件包时出现问题”：APK 的 `minSdk`
  高于手机。比如冰箱最新版要求 Android 7.0，Mi 5（API 23）只能装 3.25.1 G。
  用 `aapt2 dump badging xxx.apk | grep sdkVersion` 确认。

## 更新 APK 后 root 行为回退

`wb.sh` 会从 App 的 `files/root/` 拷 `suvd`。如果 APK 更新了但 App 还没重新
解包，旧副本会在下次 `wb.sh` 触发时覆盖 `.su/suvd`。处理：

- 打开 App 重新点一次「一键获取 Root」（会重新解包）；
- 或手动把新 `suvd` 同时放到 `.su/suvd` 和
  `/data/user/0/com.oldroot.manager/files/root/suvd`。

## `affinity: Invalid argument`

无害。`probe26` 会尝试把主线程钉到 CPU 4，参考机只有 CPU 0–3，调用失败但不影响
利用。看到这一行可以忽略。

## 设备突然重启

`panic_on_oops=1`，链错位会直接 panic。重启后一切复原，重新 `python deploy.py`
或 App 里重新点一键 root 即可。

## 重启后 root 没了

预期行为。本方案不持久化：`selinux_enforcing`、`modprobe_path` 都在内存里，
tmpfs 和 daemon 也随重启消失。
