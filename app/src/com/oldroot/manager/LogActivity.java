package com.oldroot.manager;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuItem;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.RandomAccessFile;

public class LogActivity extends Activity {

    private static final int MENU_REFRESH = 1;
    private static final int MAX_BYTES = 96 * 1024;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView text;
    private ScrollView scroll;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle("运行日志");

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF1E1E1E);

        scroll = new ScrollView(this);
        text = Ui.text(this, "读取中…", 11, 0xFFE0E0E0);
        text.setTypeface(android.graphics.Typeface.MONOSPACE);
        text.setTextIsSelectable(true);
        Ui.pad(text, this, 12, 12, 12, 12);
        scroll.addView(text, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        setContentView(root);
        load();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, MENU_REFRESH, 0, "刷新");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == MENU_REFRESH) {
            load();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void load() {
        text.setText("读取中…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String body = readTail(new File(RootManager.LOG), MAX_BYTES);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        text.setText(body);
                        scroll.post(new Runnable() {
                            @Override
                            public void run() {
                                scroll.fullScroll(ScrollView.FOCUS_DOWN);
                            }
                        });
                    }
                });
            }
        }).start();
    }

    private static String readTail(File f, int max) {
        if (!f.exists()) {
            return "日志文件不存在：\n" + f.getAbsolutePath()
                    + "\n\n说明 root 守护进程还没有启动过。";
        }
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(f, "r");
            long len = raf.length();
            long start = Math.max(0, len - max);
            byte[] buf = new byte[(int) (len - start)];
            raf.seek(start);
            raf.readFully(buf);
            String s = new String(buf, "UTF-8");
            if (start > 0) {
                int nl = s.indexOf('\n');
                if (nl >= 0 && nl + 1 < s.length()) s = "…（截断）\n" + s.substring(nl + 1);
            }
            return s.length() == 0 ? "（日志为空）" : s;
        } catch (Exception e) {
            return "读取失败：" + e + "\n\n路径：" + f.getAbsolutePath()
                    + "\n文件权限需要 root 守护进程创建。";
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Exception ignored) {
                }
            }
        }
    }
}
