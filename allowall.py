#!/usr/bin/env python3
"""One-shot "allow all": put su into PATH so every app can call it.

Installs the runnable su at /sbin/su (first entry of the Android app PATH) by
remounting the rootfs rw.  Everything stays in RAM; a reboot removes it.

    python allowall.py
    python allowall.py --serial <serial>

Requires root in the current boot (run deploy.py first).
"""
import argparse
import os
import subprocess
import sys

D = "/data/local/tmp"


def adb(serial, *args, check=True, capture=False):
    cmd = [os.environ.get("ADB", "adb")]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return subprocess.run(cmd, check=check, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def install(serial=""):
    """Install su into /sbin. Returns True on success."""
    src = f"S={D}/.su/su; [ -f \"$S\" ] || S={D}/.su.bin; "
    body = (src + "mount -o remount,rw / && chmod 0755 /sbin && "
            f"cp -f \"$S\" /sbin/su && chmod 4755 /sbin/su && "
            "mount -o remount,ro / && /sbin/su -c id")
    out = adb(serial, "shell", f"{D}/rootshell '{body}'", capture=True, check=False).stdout or ""
    print("  " + " | ".join(l for l in out.splitlines() if l.strip()))

    check = adb(serial, "shell", "/sbin/su -c id", capture=True, check=False).stdout or ""
    if "uid=0" in check:
        print("[+] /sbin/su installed — any app can now exec `su`")
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    args = ap.parse_args()

    adb(args.serial, "wait-for-device")
    who = adb(args.serial, "shell", f"{D}/.su/su -c id", capture=True, check=False).stdout or ""
    if "uid=0" not in who:
        sys.exit("[!] no root in this boot — run deploy.py first")

    print("[*] installing su into /sbin (PATH for all apps)")
    if not install(args.serial):
        sys.exit("[!] install failed — see docs/TROUBLESHOOTING.md")
    print("[*] try: adb shell su -c id")


if __name__ == "__main__":
    main()
