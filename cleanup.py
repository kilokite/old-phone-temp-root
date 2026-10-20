#!/usr/bin/env python3
"""Stop the root daemon, unmount the su tmpfs, remove residues.

The only complete reset is a reboot: selinux_enforcing and modprobe_path live in RAM.
"""
import argparse
import os
import subprocess

D = "/data/local/tmp"


def adb(serial, *args, check=False):
    cmd = [os.environ.get("ADB", "adb")]
    if serial:
        cmd += ["-s", serial]
    return subprocess.run(cmd + list(args), check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    args = ap.parse_args()

    adb(args.serial, "wait-for-device")
    print("[*] unmounting su tmpfs")
    adb(args.serial, "shell", f"{D}/rootshell 'umount {D}/.su'")
    print("[*] removing files")
    adb(args.serial, "shell",
        f"rm -rf {D}/.su {D}/.rs {D}/*.log {D}/wb.sh {D}/probe26 {D}/trig_sock {D}/rootshell {D}/su")
    print("[!] reboot to restore SELinux Enforcing and the original modprobe_path:")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}reboot")


if __name__ == "__main__":
    main()
