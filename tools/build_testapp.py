#!/usr/bin/env python3
"""给第三方应用做个最小测试包：只调用 `su -c id`，验证「其他应用拿 root」。

    python tools/build_testapp.py
产物：dist/root-testapp.apk
"""
import glob
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "testapp")
BUILD = os.path.join(ROOT, "build", "testapp")
DIST = os.path.join(ROOT, "dist")


def die(m):
    sys.exit("[!] " + m)


def find_sdk():
    for k in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(k)
        if v and os.path.isdir(v):
            return v
    g = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk")
    if os.path.isdir(g):
        return g
    die("找不到 Android SDK")


def ver_key(s):
    return [int(p) if p.isdigit() else 0 for p in s.replace("-", ".").split(".")]


def newest(parent):
    if not os.path.isdir(parent):
        return None
    items = [os.path.join(parent, d) for d in os.listdir(parent)
             if os.path.isdir(os.path.join(parent, d))]
    return sorted(items, key=lambda p: ver_key(os.path.basename(p)))[-1] if items else None


def tool(path, name):
    for n in (name, name + ".exe", name + ".bat"):
        p = os.path.join(path, n)
        if os.path.isfile(p):
            return p
    return None


def run(cmd):
    print("  " + os.path.basename(cmd[0]))
    subprocess.run(cmd, check=True)


def java(name):
    jh = os.environ.get("JAVA_HOME")
    if jh:
        p = os.path.join(jh, "bin", name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(p):
            return [p]
    return [name]


def main():
    sdk = find_sdk()
    bt = newest(os.path.join(sdk, "build-tools"))
    android_jar = os.path.join(sdk, "platforms", "android-34", "android.jar")
    if not os.path.isfile(android_jar):
        android_jar = os.path.join(newest(os.path.join(sdk, "platforms")), "android.jar")
    aapt2 = tool(bt, "aapt2")
    d8 = tool(bt, "d8")
    zipalign = tool(bt, "zipalign")
    apksigner = tool(bt, "apksigner")

    shutil.rmtree(BUILD, ignore_errors=True)
    for d in ("classes", "dex"):
        os.makedirs(os.path.join(BUILD, d))
    os.makedirs(DIST, exist_ok=True)

    base = os.path.join(BUILD, "base.apk")
    run([aapt2, "link", "-o", base,
         "-I", android_jar,
         "--manifest", os.path.join(SRC, "AndroidManifest.xml"),
         "--min-sdk-version", "21", "--target-sdk-version", "23",
         "--version-code", "1", "--version-name", "1.0"])

    srcs = glob.glob(os.path.join(SRC, "src", "**", "*.java"), recursive=True)
    classes = os.path.join(BUILD, "classes")
    run(java("javac") + ["-encoding", "UTF-8", "-source", "8", "-target", "8",
                         "-nowarn", "-Xlint:-options",
                         "-classpath", android_jar, "-d", classes] + srcs)

    jar = os.path.join(BUILD, "classes.jar")
    run(java("jar") + ["cf", jar, "-C", classes, "."])
    dex = os.path.join(BUILD, "dex")
    run([d8, "--release", "--min-api", "21", "--lib", android_jar, "--output", dex, jar])
    with zipfile.ZipFile(base, "a", zipfile.ZIP_DEFLATED) as z:
        z.write(os.path.join(dex, "classes.dex"), "classes.dex")

    aligned = os.path.join(BUILD, "aligned.apk")
    run([zipalign, "-p", "-f", "4", base, aligned])

    ks = os.path.join(ROOT, "app", "debug.keystore")
    if not os.path.isfile(ks):
        die("没有 app/debug.keystore，先跑 tools/build_apk.py")
    out = os.path.join(DIST, "root-testapp.apk")
    if os.path.isfile(out):
        os.remove(out)
    run([apksigner, "sign", "--ks", ks, "--ks-pass", "pass:android",
         "--key-pass", "pass:android", "--v1-signing-enabled", "true",
         "--v2-signing-enabled", "true", "--out", out, aligned])
    print("[+] " + out)


if __name__ == "__main__":
    main()
