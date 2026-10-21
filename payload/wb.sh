#!/system/bin/sh
# 由内核以 root 执行（modprobe_path 劫持）。
# 内核传入的 argv：<modprobe_path> -q -- net-pf-30
#
# 两种来源共用这一份脚本：
#   手机 App：__APPDIR__ / __PKG__ / __UID__ 由 App 在运行时替换；
#   PC 部署 ：二进制和脚本都放在 /data/local/tmp，__MUID__=0、__PKG__ 为空。
#
# 1) 在 /data/local/tmp/.su 挂一个 tmpfs（/data 是 nosuid，tmpfs 上才可靠执行）
# 2) 把 suvd 拷进去（先写 .new 再 mv，避免覆盖正在运行的守护进程）
# 3) 把 /sbin/su 指向它（/sbin 是应用 PATH 的第一项）
# 4) 以管理 App 的身份启动授权守护进程

D=/data/local/tmp
B=$D/.su
APP="__APPDIR__"
PKG="__PKG__"
MUID="__UID__"
EXTRA="__EXTRA__"

# 内核拉起的进程环境不可靠，全部用绝对路径
PATH=/system/bin:/system/xbin:/sbin
export PATH

/system/bin/date > $D/.payload_ran 2>/dev/null

umask 022
/system/bin/mkdir -p "$B" 2>/dev/null
if ! /system/bin/grep -q " $B " /proc/mounts 2>/dev/null; then
    /system/bin/mount -t tmpfs -o mode=0755 tmpfs "$B" 2>/dev/null
fi
/system/bin/chmod 0755 "$B" 2>/dev/null

# suvd：App 目录优先，其次 /data/local/tmp（PC 部署）
if [ -f "$APP/suvd" ]; then
    /system/bin/cp -f "$APP/suvd" "$B/suvd.new" 2>/dev/null
elif [ -f "$D/suvd" ]; then
    /system/bin/cp -f "$D/suvd" "$B/suvd.new" 2>/dev/null
fi
if [ -f "$B/suvd.new" ]; then
    /system/bin/chmod 0755 "$B/suvd.new" 2>/dev/null
    /system/bin/mv -f "$B/suvd.new" "$B/suvd" 2>/dev/null
fi

# su -> suvd（多调用：argv[0] 是 su 时走客户端）
/system/bin/rm -f "$B/su" 2>/dev/null
/system/bin/ln -s "$B/suvd" "$B/su" 2>/dev/null

# 应用默认 PATH 的第一项就是 /sbin；只在有管理 App 时改 /sbin
if [ -n "$MUID" ] && [ "$MUID" != "0" ] && [ -x "$B/suvd" ]; then
    if /system/bin/mount -o remount,rw / 2>/dev/null; then
        # 很多 ROM 的 /sbin 是 0750（root:root），应用没有 x 权限，
        # 光放 /sbin/su 也没用，必须把目录本身放开。
        /system/bin/chmod 0755 /sbin 2>/dev/null
        /system/bin/rm -f /sbin/su 2>/dev/null
        /system/bin/ln -s "$B/suvd" /sbin/su 2>/dev/null
        /system/bin/chmod 0755 /sbin/su 2>/dev/null
        /system/bin/mount -o remount,ro / 2>/dev/null
    fi
fi

# 启动（或替换）授权守护进程
if [ -n "$PKG" ] && [ "$MUID" != "0" ]; then
    "$B/suvd" -d --base "$B" --manager "$PKG" --manager-uid "$MUID" \
        --timeout 60 --restart $EXTRA
else
    "$B/suvd" -d --base "$B" --timeout 60 --restart $EXTRA
fi

exit 0
