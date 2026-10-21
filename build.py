#!/usr/bin/env python3
"""交叉编译全部设备端二进制（静态 aarch64，Android API 23）。

    python build.py
    ANDROID_NDK_HOME=/path/to/ndk python build.py
    python build.py --define A_MODPROBE_PATH=0xffffffc001e37ce0
"""
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
API = os.environ.get("API", "23")
HOSTS = ("windows-x86_64", "linux-x86_64", "darwin-x86_64")


def find_ndk():
    """按环境变量 / SDK 默认目录顺序找 NDK。"""
    env = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if env and os.path.isdir(env):
        return env
    candidates = []
    local = os.environ.get("LOCALAPPDATA")
    home = os.path.expanduser("~")
    if local:
        candidates += glob.glob(os.path.join(local, "Android", "Sdk", "ndk", "*"))
    candidates += glob.glob(os.path.join(home, "Android", "Sdk", "ndk", "*"))
    candidates += glob.glob("/opt/android-ndk*")
    candidates = [c for c in candidates if os.path.isdir(c)]
    if not candidates:
        sys.exit("错误：找不到 Android NDK，请设置 ANDROID_NDK_HOME")
    return sorted(candidates)[-1]


def find_cc(ndk):
    """按当前系统挑 aarch64 clang（Windows 用 .cmd 包装）。"""
    if os.name == "nt":
        names = [f"aarch64-linux-android{API}-clang.cmd", "clang.exe"]
    else:
        names = [f"aarch64-linux-android{API}-clang", "clang"]
    for host in HOSTS:
        base = os.path.join(ndk, "toolchains", "llvm", "prebuilt", host, "bin")
        if not os.path.isdir(base):
            continue
        for name in names:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    sys.exit(f"错误：{ndk} 下没有 aarch64 clang")


def run_cc(cc, args):
    """调用编译器；Windows 的 .cmd 包装需要经过 cmd.exe。"""
    if os.name == "nt" and cc.lower().endswith(".cmd"):
        cmd = ["cmd", "/c", cc] + args
    else:
        cmd = [cc] + args
    print("  编译 " + os.path.basename(args[-1]))
    subprocess.run(cmd, check=True)


def main(argv):
    # 透传给 probe26 的宏，例如 --define A_MODPROBE_PATH=0x...
    defines = []
    it = iter(argv)
    for a in it:
        if a == "--define":
            defines.append("-D" + next(it))
        elif a.startswith("-D"):
            defines.append(a)

    ndk = find_ndk()
    cc = find_cc(ndk)
    print(f"NDK    ：{ndk}")
    print(f"编译器 ：{cc}")

    bindir = os.path.join(ROOT, "bin")
    os.makedirs(bindir, exist_ok=True)
    targets = {
        "probe26": ["src/probe26.c"] + defines,
        "trig_sock": ["src/trig_sock.c"],
        "suvd": ["src/suvd.c"],
    }
    for name, srcs in targets.items():
        out = os.path.join(bindir, name)
        run_cc(cc, ["-O2", "-static", "-w", "-o", out] + [os.path.join(ROOT, s) for s in srcs])

    if os.name != "nt":
        for n in targets:
            os.chmod(os.path.join(bindir, n), 0o755)
    print("已生成：" + "、".join(sorted(os.listdir(bindir))))


if __name__ == "__main__":
    main(sys.argv[1:])
