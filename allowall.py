#!/usr/bin/env python3
"""一键全放行：把 su 装进 /sbin，让所有应用都能直接调用。

安装的是 rootshell 的客户端形态：应用执行 /sbin/su 后，命令通过 socket
交给全 capability 的守护进程执行，所以拿到的是完整 root（不是只能 setuid 的
受限 root）。全部只在内存里，重启即消失。

    python allowall.py
    python allowall.py --serial <serial>

前提：本次开机已经有 root（先跑 deploy.py）。
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
    """把 su 客户端装到 /sbin/su 并验证；成功返回 True。"""
    # /sbin/su 是 rootshell 的客户端形态：命令转发给守护进程，拿完整 capability
    body = ("mount -o remount,rw / && chmod 0755 /sbin && "
            f"cp -f {D}/rootshell /sbin/su && chmod 0755 /sbin/su && "
            "mount -o remount,ro / && /sbin/su -c id")
    out = adb(serial, "shell", f"{D}/rootshell '{body}'", capture=True, check=False).stdout or ""
    print("  " + " | ".join(l for l in out.splitlines() if l.strip()))

    check = adb(serial, "shell", "/sbin/su -c id", capture=True, check=False).stdout or ""
    if "uid=0" in check:
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

    print("[*] 把 su 装进 /sbin（所有应用的 PATH）")
    if not install(args.serial):
        sys.exit("[!] 安装失败，见 docs/TROUBLESHOOTING.md")
    print("[*] 试试：adb shell su -c id")


if __name__ == "__main__":
    main()
