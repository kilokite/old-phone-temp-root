# 排错

## `adb: more than one device/emulator`

机器上还有别的设备或模拟器。用序列号：

```bash
python deploy.py --serial <serial>
```

## `probe26` 的 `readv` 返回值不是 69708

说明链没有按设计推进（steal 抢错槽、块边界错位、或有别的 kmalloc-512 分配插队）。

- 直接重跑一次；仍不行就重启后再跑。
- 不要用这个返回值判断"写没写成功"——以 `getenforce` 为准。
- 日志在 `/data/local/tmp/probe26.log`。

## `getenforce` 仍然是 `Enforcing`

`selinux_enforcing` 的写入没生效，通常同上：链没命中。重跑或重启重试。

## `trig_sock` 返回 `errno=97`（EAFNOSUPPORT）

这是**正常的**：`socket(30)` 必然失败，目的只是让内核走到
`request_module("net-pf-30")`。判断成功与否看 `modprobe_path` 有没有被改写、
以及 `/data/local/tmp/.su/su` 是否出现。

## payload 没执行

- `modprobe_path` 是否真的是 `/data/local/tmp/wb.sh`（长度 ≤ 23 字符，
  写入长度是 `align8(len+1)`）。
- `wb.sh` 必须有可执行位，且第一行是 `#!/system/bin/sh`。
- usermodehelper 的环境没有 `PATH`，脚本里所有命令都要写绝对路径。

## `su: not found`

预期行为：本方案不写 `/system`，`su` 只存在于 `/data/local/tmp/.su/su`，不在 `PATH` 里。
直接调绝对路径，或在 shell 里：

```sh
export PATH=/data/local/tmp/.su:$PATH
su
```

`/data/local/tmp/su` 是**源文件**（非 setuid），不要直接运行，它会报
`su: cannot become root`。

## `affinity: Invalid argument`

无害。`probe26` 会尝试把主线程钉到 CPU 4，参考机只有 CPU 0–3，调用失败但不影响利用
（实测未钉核也能稳定命中）。看到这一行可以忽略。

## payload 到底跑没跑

`payload/wb.sh` 每次执行都会写 `/data/local/tmp/.payload_ran`（时间戳，属主 root）。
`trig_sock` 之后这个文件的时间戳没变，说明 `request_module` 没触发或
`modprobe_path` 不对。

## `su: cannot become root` / `su -c id` 还是 `uid=2000`

- `/data` 是 `nosuid`，`su` 必须在 tmpfs 上：确认
  `mount | grep .su` 能看到 `/data/local/tmp/.su`。
- 如果 tmpfs 没挂上（比如上次卸载残留），先 `umount /data/local/tmp/.su`
  再重新触发。
- SELinux 必须是 Permissive（先跑完 `probe26`）。

## 设备突然重启

`panic_on_oops=1`，链错位会直接 panic。重启后一切复原，重新 `python deploy.py` 即可。
连续多次失败时优先检查是否有其他进程在频繁使用 binder（后台应用、系统更新）。

## 重启后 root 没了

预期行为。本方案不持久化：`selinux_enforcing`、`modprobe_path` 都在内存里，
tmpfs 和 daemon 也随重启消失。

## 全放行失败（`/sbin/su` 不存在或提权失败）

- `mount -o remount,rw /` 在部分 ROM 上会被拒绝：确认当前确实有 root（`getenforce` 为 Permissive），再重试。
- 写入成功但执行仍非 root：确认 `/sbin` 所在挂载没有 `nosuid`；被 nosuid 的话只能退回 tmpfs 覆盖 `/system/xbin`（会遮住原有命令）。
- 重启后 `/sbin/su` 消失是预期行为。
