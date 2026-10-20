#!/usr/bin/env python3
"""一键全放行（受限 root）：把 setuid 的 su 装进 /sbin，所有应用可直接调用。

注意：应用执行 setuid-root 只能拿到自己的 capability bounding set（Android 上
是 0xc0），能 setuid 到 0，但绕不过 DAC（例如 ls /data 会失败）。要完整 root
用 suclient.py。

    python allowall.py
    python allowall.py --serial <serial>
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
    """把 setuid su 装到 /sbin/su 并验证；成功返回 True。"""
    # 源文件优先用 tmpfs 上的可执行副本，没有再用 .su.bin
    src = f"S={D}/.su/su; [ -f \"$S\" ] || S={D}/.su.bin; "
    body = (src + "mount -o remount,rw / && chmod 0755 /sbin && "
            f"cp -f \"$S\" /sbin/su && chmod 4755 /sbin/su && "
            "mount -o remount,ro / && /sbin/su -c id")
    out = adb(serial, "shell", f"{D}/rootshell '{body}'", capture=True, check=False).stdout or ""
    print("  " + " | ".join(l for l in out.splitlines() if l.strip()))

    check = adb(serial, "shell", "/sbin/su -c id", capture=True, check=False).stdout or ""
    if "uid=0" in check:
        print("[+] /sbin/su 已安装（setuid，受限 root：无 CAP_DAC_OVERRIDE）")
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

    print("[*] 把 setuid su 装进 /sbin（所有应用的 PATH）")
    if not install(args.serial):
        sys.exit("[!] 安装失败，见 docs/TROUBLESHOOTING.md")
    print("[*] 试试：adb shell su -c id")


if __name__ == "__main__":
    main()
