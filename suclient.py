#!/usr/bin/env python3
"""一键客户端 su：把 rootshell 的客户端形态装成 /sbin/su。

应用执行 /sbin/su 后，命令通过 /data/local/tmp/.rs 交给全 capability 的守护
进程执行，拿到的是完整 root（CapEff 0x3fffffffff），不是 setuid 的受限 root。

    python suclient.py
    python suclient.py --serial <serial>

前提：本次开机已经有 root，且 rootshell 守护进程在跑（deploy.py 会拉起）。
"""
import argparse
import os
import subprocess
import sys

D = "/data/local/tmp"


def adb(serial, *args, check=True, capture=False):
    """调用 adb，统一 UTF-8 解码。"""
    cmd = [os.environ.get("ADB", "adb")]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return subprocess.run(cmd, check=check, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def install(serial=""):
    """把 rootshell 客户端装到 /sbin/su 并验证完整 capability；成功返回 True。"""
    body = ("mount -o remount,rw / && chmod 0755 /sbin && "
            f"cp -f {D}/rootshell /sbin/su && chmod 0755 /sbin/su && "
            "mount -o remount,ro / && /sbin/su -c \"id; grep CapEff /proc/self/status\"")
    out = adb(serial, "shell", f"{D}/rootshell '{body}'", capture=True, check=False).stdout or ""
    print("  " + " | ".join(l for l in out.splitlines() if l.strip()))

    check = adb(serial, "shell", "/sbin/su -c id", capture=True, check=False).stdout or ""
    caps = adb(serial, "shell", "/sbin/su -c 'grep CapEff /proc/self/status'",
               capture=True, check=False).stdout or ""
    if "uid=0" in check and "3fffffffff" in caps:
        print("[+] /sbin/su 已安装（daemon 客户端，完整 root）")
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    args = ap.parse_args()

    adb(args.serial, "wait-for-device")
    who = adb(args.serial, "shell", f"{D}/.su/su -c id", capture=True, check=False).stdout or ""
    if "uid=0" not in who:
        sys.exit("[!] 本次开机还没有 root——先运行 deploy.py")

    print("[*] 把客户端 su 装进 /sbin（命令转发给全 capability 的守护进程）")
    if not install(args.serial):
        sys.exit("[!] 安装失败，见 docs/TROUBLESHOOTING.md")
    print("[*] 试试：adb shell su -c id")


if __name__ == "__main__":
    main()
