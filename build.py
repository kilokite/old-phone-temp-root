#!/usr/bin/env python3
"""Cross-compile all device binaries (static aarch64, Android API 23).

    python build.py
    ANDROID_NDK_HOME=/path/to/ndk python build.py
    python build.py --define A_MODPROBE_PATH=0xffffffc001e37ce0
"""
import glob
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
API = os.environ.get("API", "23")
HOSTS = ("windows-x86_64", "linux-x86_64", "darwin-x86_64")


def find_ndk():
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
        sys.exit("error: Android NDK not found; set ANDROID_NDK_HOME")
    return sorted(candidates)[-1]


def find_cc(ndk):
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
    sys.exit(f"error: no aarch64 clang under {ndk}")


def run_cc(cc, args):
    if os.name == "nt" and cc.lower().endswith(".cmd"):
        cmd = ["cmd", "/c", cc] + args
    else:
        cmd = [cc] + args
    print("  " + " ".join(os.path.basename(c) for c in cmd[:2]) + " ...")
    subprocess.run(cmd, check=True)


def main(argv):
    defines = []
    it = iter(argv)
    for a in it:
        if a == "--define":
            defines.append("-D" + next(it))
        elif a.startswith("-D"):
            defines.append(a)

    ndk = find_ndk()
    cc = find_cc(ndk)
    print(f"NDK : {ndk}")
    print(f"CC  : {cc}")

    bindir = os.path.join(ROOT, "bin")
    os.makedirs(bindir, exist_ok=True)
    targets = {
        "probe26": ["src/probe26.c"] + defines,
        "trig_sock": ["src/trig_sock.c"],
        "rootshell": ["src/rootshell.c"],
        "su": ["src/su.c"],
    }
    for name, srcs in targets.items():
        out = os.path.join(bindir, name)
        run_cc(cc, ["-O2", "-static", "-w", "-o", out] + [os.path.join(ROOT, s) for s in srcs])

    if os.name != "nt":
        for n in targets:
            os.chmod(os.path.join(bindir, n), 0o755)
    print("built:", ", ".join(sorted(os.listdir(bindir))))


if __name__ == "__main__":
    main(sys.argv[1:])
