package com.oldroot.manager;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * 与 root 守护进程 suvd 的客户端。socket 是文件系统命名空间里的
 * /data/local/tmp/.su/suvd.sock，所以只能用 LocalSocket。
 */
public final class RootManager {

    public static final String BASE = "/data/local/tmp/.su";
    public static final String SOCK = BASE + "/suvd.sock";
    public static final String LOG = BASE + "/suvd.log";
    public static final String POLICY = BASE + "/policy.tsv";

    private static final int SO_TIMEOUT = 20000;
    private static final int MAX_OUTPUT = 8 * 1024 * 1024;

    public static final class Status {
        public String version = "";
        public int managerUid = -1;
        public int timeout = 60;
        public int entries = 0;
    }

    public static final class Entry {
        public int uid;
        public boolean allow;
    }

    public static final class ExecResult {
        public int code = 1;
        public boolean denied;
        public String message = "";
        public String output = "";
    }

    private RootManager() {
    }

    private static LocalSocket open() throws IOException {
        LocalSocket s = new LocalSocket();
        // 注意：Android 6 的 connect(addr, timeout) 会抛 UnsupportedOperationException
        // （LocalSocket.java:276），只能用单参数版本。
        s.connect(new LocalSocketAddress(SOCK, LocalSocketAddress.Namespace.FILESYSTEM));
        try {
            s.setSoTimeout(SO_TIMEOUT);
        } catch (UnsupportedOperationException ignored) {
            // 老系统不支持读超时；协议本身都有应答，问题不大
        }
        return s;
    }

    private static void close(LocalSocket s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static void send(OutputStream out, String text) throws IOException {
        out.write(text.getBytes("UTF-8"));
        out.flush();
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(64);
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                return new String(buf.toByteArray(), "UTF-8");
            }
            buf.write(c);
            if (buf.size() > 4096) {
                throw new IOException("header too long");
            }
        }
        throw new IOException("connection closed");
    }

    private static byte[] readExactly(InputStream in, int n) throws IOException {
        byte[] data = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(data, off, n - off);
            if (r < 0) {
                throw new IOException("unexpected EOF");
            }
            off += r;
        }
        return data;
    }

    public static boolean isRunning() {
        try {
            status();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static Status status() throws IOException {
        LocalSocket s = open();
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            send(out, "V\n");
            String line = readLine(in);
            if (!line.startsWith("V ")) {
                throw new IOException("bad status: " + line);
            }
            String[] p = line.split(" ");
            Status st = new Status();
            if (p.length > 1) st.version = p[1];
            if (p.length > 2) st.managerUid = parseInt(p[2], -1);
            if (p.length > 3) st.timeout = parseInt(p[3], 60);
            if (p.length > 5) st.entries = parseInt(p[5], 0);
            return st;
        } finally {
            close(s);
        }
    }

    public static List<Entry> list() throws IOException {
        LocalSocket s = open();
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            send(out, "L\n");
            String line = readLine(in);
            if (line.startsWith("E ")) {
                throw new IOException(line.substring(2));
            }
            if (!line.startsWith("L ")) {
                throw new IOException("bad list: " + line);
            }
            int len = parseInt(line.substring(2).trim(), 0);
            byte[] data = readExactly(in, len);
            String text = new String(data, "UTF-8");
            List<Entry> entries = new ArrayList<Entry>();
            for (String ln : text.split("\n")) {
                if (ln.length() == 0) continue;
                String[] f = ln.split("\t");
                if (f.length < 2) continue;
                Entry e = new Entry();
                e.uid = parseInt(f[0], -1);
                e.allow = "allow".equals(f[1]);
                if (e.uid > 0) entries.add(e);
            }
            return entries;
        } finally {
            close(s);
        }
    }

    public static ExecResult exec(String command) throws IOException {
        LocalSocket s = open();
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            byte[] cmd = command.getBytes("UTF-8");
            send(out, "Q " + cmd.length + "\n");
            out.write(cmd);
            out.flush();

            String line = readLine(in);
            ExecResult r = new ExecResult();
            if (line.startsWith("D ")) {
                r.denied = true;
                r.message = line.substring(2);
                r.code = 1;
                return r;
            }
            if (line.startsWith("E ")) {
                throw new IOException(line.substring(2));
            }
            if (!line.equals("O")) {
                throw new IOException("bad reply: " + line);
            }

            ByteArrayOutputStream buf = new ByteArrayOutputStream(8192);
            byte[] chunk = new byte[8192];
            while (true) {
                int n = in.read(chunk);
                if (n < 0) break;
                buf.write(chunk, 0, n);
                if (buf.size() > MAX_OUTPUT) break;
            }
            byte[] all = buf.toByteArray();
            return parseExec(all);
        } finally {
            close(s);
        }
    }

    /** 输出尾部是 "\n__SUVX_<nonce>_<code>__\n"；从中取退出码并剥掉。 */
    private static ExecResult parseExec(byte[] all) {
        ExecResult r = new ExecResult();
        byte[] marker = "\n__SUVX_".getBytes();
        int pos = -1;
        for (int i = all.length - marker.length; i >= 0; i--) {
            boolean match = true;
            for (int j = 0; j < marker.length; j++) {
                if (all[i + j] != marker[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                pos = i;
                break;
            }
        }
        if (pos < 0) {
            r.code = 1;
            r.output = new String(all, 0, all.length);
            return r;
        }
        int p = pos + marker.length;
        while (p < all.length && all[p] != '_') p++;
        if (p < all.length) {
            int q = p + 1;
            int code = 0;
            boolean digits = false;
            while (q < all.length && all[q] >= '0' && all[q] <= '9') {
                code = code * 10 + (all[q] - '0');
                q++;
                digits = true;
            }
            if (digits) r.code = code;
        }
        r.output = new String(all, 0, Math.max(0, pos));
        return r;
    }

    public static void setPolicy(int uid, boolean allow) throws IOException {
        admin("P " + uid + " " + (allow ? "allow" : "deny") + "\n");
    }

    public static void removePolicy(int uid) throws IOException {
        admin("X " + uid + "\n");
    }

    public static void resetPolicy() throws IOException {
        admin("Z\n");
    }

    public static void stopDaemon() throws IOException {
        admin("K\n");
    }

    public static boolean answer(String id, String token, String decision) throws IOException {
        LocalSocket s = open();
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            send(out, "A " + id + " " + token + " " + decision + "\n");
            String line = readLine(in);
            return line.equals("OK");
        } finally {
            close(s);
        }
    }

    private static void admin(String request) throws IOException {
        LocalSocket s = open();
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            send(out, request);
            String line = readLine(in);
            if (!line.equals("OK")) {
                if (line.startsWith("E ")) throw new IOException(line.substring(2));
                throw new IOException("bad reply: " + line);
            }
        } finally {
            close(s);
        }
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }
}
