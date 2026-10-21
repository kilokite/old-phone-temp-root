#!/usr/bin/env python3
"""停掉授权守护进程、删除 /sbin/su、清理残留。

彻底恢复只能重启：selinux_enforcing 和 modprobe_path 都在内存里，
/data/local/tmp/.su 是 tmpfs，重启后自动消失。
"""
import argparse
import os
import subprocess
import time

D = "/data/local/tmp"


def adb(serial, *args, check=False):
    """调用 adb，统一 UTF-8 解码。"""
    cmd = [os.environ.get("ADB", "adb")]
    if serial:
        cmd += ["-s", serial]
    return subprocess.run(cmd + list(args), check=check, text=True, encoding="utf-8",
                          errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    args = ap.parse_args()

    adb(args.serial, "wait-for-device")

    print("[*] 删除 /sbin/su 并停掉守护进程")
    out = adb(args.serial, "shell",
              f"{D}/.su/su -c 'rm -f /sbin/su; kill $(cat {D}/.su/suvd.pid) 2>/dev/null; "
              f"rm -f {D}/.su/suvd.pid {D}/.su/suvd.sock'")
    if out.stdout:
        print("  " + out.stdout.strip().replace("\n", " | "))
    time.sleep(0.5)

    print("[*] 清理文件")
    adb(args.serial, "shell",
        f"rm -rf {D}/.su {D}/*.log {D}/.payload_ran {D}/wb.sh "
        f"{D}/probe26 {D}/trig_sock {D}/suvd")

    print("[!] 重启以恢复 SELinux Enforcing 和原始 modprobe_path：")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}reboot")


if __name__ == "__main__":
    main()
