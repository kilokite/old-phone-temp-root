#!/usr/bin/env python3
"""停掉 root 守护进程、卸载 su 的 tmpfs、清理残留。

彻底恢复只能重启：selinux_enforcing 和 modprobe_path 都在内存里。
"""
import argparse
import os
import subprocess

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
    print("[*] 卸载 su 的 tmpfs")
    adb(args.serial, "shell", f"{D}/rootshell 'umount {D}/.su'")
    print("[*] 删除 /sbin/su")
    adb(args.serial, "shell", f"{D}/rootshell 'rm -f /sbin/su'")
    print("[*] 清理文件")
    adb(args.serial, "shell",
        f"rm -rf {D}/.su {D}/.rs {D}/*.log {D}/.payload_ran {D}/.su.bin "
        f"{D}/wb.sh {D}/probe26 {D}/trig_sock {D}/rootshell {D}/su")
    print("[!] 重启以恢复 SELinux Enforcing 和原始 modprobe_path：")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}reboot")


if __name__ == "__main__":
    main()
