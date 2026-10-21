package com.oldroot.testapp;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * 第三方应用视角：只调用 `su -c`，看不到任何内部机制。
 * 用来验证「其他应用怎么拿 root」。
 */
public class MainActivity extends Activity {

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView out;
    private Button again;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);

        ScrollView sc = new ScrollView(this);
        out = new TextView(this);
        out.setTextSize(13);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextIsSelectable(true);
        out.setPadding(32, 32, 32, 32);
        sc.addView(out, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(sc, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        again = new Button(this);
        again.setAllCaps(false);
        again.setText("再执行一次 su");
        again.setOnClickListener(new android.view.View.OnClickListener() {
            @Override
            public void onClick(android.view.View v) {
                runTest();
            }
        });
        root.addView(again, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 140));

        setContentView(root);
        runTest();
    }

    private void runTest() {
        again.setEnabled(false);
        out.setText("调用：su -c \"id; getenforce\"\n\n"
                + "PATH=" + String.valueOf(System.getenv("PATH")) + "\n\n等待授权…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                String text;
                try {
                    ProcessBuilder pb = new ProcessBuilder("su", "-c", "id; getenforce");
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    ByteArrayOutputStream buf = new ByteArrayOutputStream();
                    InputStream in = p.getInputStream();
                    byte[] b = new byte[4096];
                    int n;
                    while ((n = in.read(b)) > 0) buf.write(b, 0, n);
                    int code = p.waitFor();
                    text = "su 退出码：" + code + "\n\n" + new String(buf.toByteArray(), "UTF-8");
                } catch (Throwable t) {
                    text = "调用失败：" + t;
                }
                final String s = text;
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        out.setText(s);
                        again.setEnabled(true);
                    }
                });
            }
        }).start();
    }
}
