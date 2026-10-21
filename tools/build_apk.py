#!/usr/bin/env python3
"""不用 Gradle，直接用 SDK 里的 aapt2 / d8 / zipalign / apksigner 打 APK。

    python build.py                 # 先编设备端二进制（含 suvd）
    python tools/build_apk.py       # 再打 APK

产物：dist/oldroot-manager.apk
依赖：ANDROID_HOME（或默认的 %LOCALAPPDATA%\\Android\\Sdk）、JDK 8+。
"""
import glob
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app")
BUILD = os.path.join(ROOT, "build", "app")
DIST = os.path.join(ROOT, "dist")
ASSETS = os.path.join(APP, "assets")
BIN = os.path.join(ROOT, "bin")
ABI = "arm64-v8a"
PKG = "com.oldroot.manager"
VERSION_CODE = "1"
VERSION_NAME = "1.0"


def die(msg):
    sys.exit("[!] " + msg)


def find_sdk():
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(key)
        if v and os.path.isdir(v):
            return v
    local = os.environ.get("LOCALAPPDATA")
    guess = os.path.join(local, "Android", "Sdk") if local else None
    if guess and os.path.isdir(guess):
        return guess
    home = os.path.expanduser("~")
    for p in (os.path.join(home, "Android", "Sdk"), "/opt/android-sdk"):
        if os.path.isdir(p):
            return p
    die("找不到 Android SDK，请设置 ANDROID_HOME")


def version_key(name):
    parts = []
    for p in name.replace("-", ".").split("."):
        parts.append(int(p) if p.isdigit() else 0)
    return parts


def newest_dir(parent):
    if not os.path.isdir(parent):
        return None
    items = [os.path.join(parent, d) for d in os.listdir(parent)
             if os.path.isdir(os.path.join(parent, d))]
    if not items:
        return None
    return sorted(items, key=lambda p: version_key(os.path.basename(p)))[-1]


def pick_platform(sdk):
    if os.path.isdir(os.path.join(sdk, "platforms", "android-34")):
        return os.path.join(sdk, "platforms", "android-34")
    return newest_dir(os.path.join(sdk, "platforms"))


def exe(path, name):
    for cand in (os.path.join(path, name),
                 os.path.join(path, name + ".exe"),
                 os.path.join(path, name + ".bat")):
        if os.path.isfile(cand):
            return cand
    return None


def run(cmd, **kw):
    print("  " + os.path.basename(cmd[0]) + " " + " ".join(
        os.path.basename(c) if os.sep in c else c for c in cmd[1:]))
    subprocess.run(cmd, check=True, **kw)


def java_tool(name):
    home = os.environ.get("JAVA_HOME")
    if home:
        p = os.path.join(home, "bin", name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(p):
            return [p]
    return [name]


def main():
    sdk = find_sdk()
    bt = newest_dir(os.path.join(sdk, "build-tools"))
    if not bt:
        die("SDK 里没有 build-tools")
    platform = pick_platform(sdk)
    if not platform or not os.path.isfile(os.path.join(platform, "android.jar")):
        die("SDK 里没有 platforms/android-*")

    aapt2 = exe(bt, "aapt2")
    d8 = exe(bt, "d8")
    zipalign = exe(bt, "zipalign")
    apksigner = exe(bt, "apksigner")
    for tool, name in ((aapt2, "aapt2"), (d8, "d8"), (zipalign, "zipalign"),
                       (apksigner, "apksigner")):
        if not tool:
            die(f"build-tools 里找不到 {name}")

    for b in ("suvd", "probe26"):
        if not os.path.isfile(os.path.join(BIN, b)):
            die(f"bin/{b} 不存在，先运行 python build.py")

    shutil.rmtree(BUILD, ignore_errors=True)
    for d in ("classes", "dex", "gen", "compiled"):
        os.makedirs(os.path.join(BUILD, d), exist_ok=True)
    os.makedirs(DIST, exist_ok=True)

    # ---- 资源 / 资产 ----
    print("[*] 准备资源与二进制资产")
    assets_abi = os.path.join(ASSETS, ABI)
    os.makedirs(assets_abi, exist_ok=True)
    for b in ("suvd", "probe26"):
        shutil.copy2(os.path.join(BIN, b), os.path.join(assets_abi, b))
    shutil.copy2(os.path.join(ROOT, "payload", "wb.sh"), os.path.join(ASSETS, "wb.sh.in"))

    res_zip = os.path.join(BUILD, "res.zip")
    run([aapt2, "compile", "--dir", os.path.join(APP, "res"), "-o", res_zip])

    base_apk = os.path.join(BUILD, "base.apk")
    gen = os.path.join(BUILD, "gen")
    run([aapt2, "link", "-o", base_apk,
         "-I", os.path.join(platform, "android.jar"),
         "--manifest", os.path.join(APP, "AndroidManifest.xml"),
         "-A", ASSETS,
         "--java", gen,
         "--min-sdk-version", "21",
         "--target-sdk-version", "23",
         "--version-code", VERSION_CODE,
         "--version-name", VERSION_NAME,
         res_zip])

    # ---- Java ----
    print("[*] 编译 Java")
    sources = glob.glob(os.path.join(APP, "src", "**", "*.java"), recursive=True)
    sources += glob.glob(os.path.join(gen, "**", "*.java"), recursive=True)
    classes = os.path.join(BUILD, "classes")
    cmd = java_tool("javac") + [
        "-encoding", "UTF-8", "-source", "8", "-target", "8",
        "-Xlint:-options", "-nowarn",
        "-classpath", os.path.join(platform, "android.jar"),
        "-d", classes,
    ] + sources
    run(cmd)

    # ---- dex ----
    print("[*] 生成 classes.dex")
    jar_path = os.path.join(BUILD, "classes.jar")
    run(java_tool("jar") + ["cf", jar_path, "-C", classes, "."])
    dexdir = os.path.join(BUILD, "dex")
    run([d8, "--release", "--min-api", "21",
         "--lib", os.path.join(platform, "android.jar"),
         "--output", dexdir, jar_path])

    dex = os.path.join(dexdir, "classes.dex")
    if not os.path.isfile(dex):
        die("d8 没有产出 classes.dex")

    with zipfile.ZipFile(base_apk, "a", zipfile.ZIP_DEFLATED) as z:
        z.write(dex, "classes.dex")

    # ---- 对齐 / 签名 ----
    aligned = os.path.join(BUILD, "aligned.apk")
    run([zipalign, "-p", "-f", "4", base_apk, aligned])

    keystore = os.path.join(APP, "debug.keystore")
    if not os.path.isfile(keystore):
        print("[*] 生成调试签名")
        run(java_tool("keytool") + [
            "-genkeypair", "-keystore", keystore,
            "-storepass", "android", "-keypass", "android",
            "-alias", "androiddebugkey",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-dname", "CN=Android Debug,O=Android,C=US",
        ])

    out = os.path.join(DIST, "oldroot-manager.apk")
    if os.path.isfile(out):
        os.remove(out)
    run([apksigner, "sign",
         "--ks", keystore, "--ks-pass", "pass:android",
         "--key-pass", "pass:android",
         "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
         "--out", out, aligned])
    run([apksigner, "verify", "--print-certs", out])

    size = os.path.getsize(out)
    print(f"\n[+] {out}  ({size / 1024 / 1024:.1f} MB)")
    print(f"    minSdk 21 / targetSdk 23 / {ABI}")
    print(f"    安装：adb install -r \"{out}\"")


if __name__ == "__main__":
    main()
