#!/usr/bin/env python3
"""把 tools/uiauto 打成 uiautomator runtest 用的 jar。"""
import glob
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build", "uiauto")
SDK = os.environ.get("ANDROID_HOME") or os.path.join(
    os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk")
ANDROID_JAR = os.path.join(SDK, "platforms", "android-34", "android.jar")
UIAUTO_JAR = os.path.join(SDK, "platforms", "android-34", "uiautomator.jar")
TEST_BASE_JAR = os.path.join(SDK, "platforms", "android-34", "optional", "android.test.base.jar")
CP = [ANDROID_JAR, UIAUTO_JAR, TEST_BASE_JAR]


def ver(s):
    return [int(p) if p.isdigit() else 0 for p in s.split(".")]


def main():
    bt = sorted(glob.glob(os.path.join(SDK, "build-tools", "*")), key=ver)[-1]
    d8 = os.path.join(bt, "d8.bat" if os.name == "nt" else "d8")
    if not os.path.isfile(ANDROID_JAR) or not os.path.isfile(UIAUTO_JAR):
        sys.exit("[!] 需要 platforms/android-34 里的 android.jar / uiautomator.jar")

    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(os.path.join(BUILD, "classes"))
    os.makedirs(os.path.join(BUILD, "dex"))

    srcs = glob.glob(os.path.join(ROOT, "tools", "uiauto", "src", "**", "*.java"), recursive=True)
    subprocess.run(["javac", "-encoding", "UTF-8", "-source", "8", "-target", "8", "-nowarn",
                    "-classpath", os.pathsep.join(CP),
                    "-d", os.path.join(BUILD, "classes")] + srcs, check=True)

    jar = os.path.join(BUILD, "classes.jar")
    subprocess.run(["jar", "cf", jar, "-C", os.path.join(BUILD, "classes"), "."], check=True)
    libs = []
    for c in CP:
        libs += ["--lib", c]
    subprocess.run([d8, "--release", "--min-api", "21"] + libs +
                   ["--output", os.path.join(BUILD, "dex"), jar], check=True)

    out = os.path.join(ROOT, "dist", "uiauto.jar")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(os.path.join(BUILD, "dex", "classes.dex"), "classes.dex")
    print("[+] " + out)


if __name__ == "__main__":
    main()
