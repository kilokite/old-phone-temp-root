#!/system/bin/sh
# 用 sendevent 注入一次点击（MIUI 禁用了 adb input 时用）
# 用法：tap.sh X Y
X=$1
Y=$2
DEV=/dev/input/event2
SE=/system/bin/sendevent

$SE $DEV 3 47 0
$SE $DEV 3 57 1001
$SE $DEV 3 53 "$X"
$SE $DEV 3 54 "$Y"
$SE $DEV 3 48 6
$SE $DEV 3 58 50
$SE $DEV 1 330 1
$SE $DEV 0 0 0
usleep 60000 2>/dev/null || sleep 0.06
$SE $DEV 3 47 0
$SE $DEV 3 57 -1
$SE $DEV 1 330 0
$SE $DEV 0 0 0
