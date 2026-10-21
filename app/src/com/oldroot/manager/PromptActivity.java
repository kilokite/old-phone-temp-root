package com.oldroot.manager;

import android.app.Activity;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.util.ArrayList;

/**
 * 授权弹窗。守护进程用 `am start -n com.oldroot.manager/.PromptActivity` 拉起，
 * 通过 id + token 回答；超时由两边各自兜底（这里主动发 deny）。
 */
public class PromptActivity extends Activity {

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ArrayList<Intent> pending = new ArrayList<Intent>();

    private String id;
    private String token;
    private String command;
    private int uid;
    private int timeout = 60;

    private boolean answering;
    private int generation;
    private long deadline;

    private TextView countdown;
    private ProgressBar progress;
    private CheckBox remember;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED
                | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
                | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        setFinishOnTouchOutside(false);
        bind(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (answering) {
            pending.add(intent);
        } else {
            bind(intent);
        }
    }

    private void bind(Intent intent) {
        id = intent.getStringExtra("id");
        token = intent.getStringExtra("token");
        command = intent.getStringExtra("cmd");
        String u = intent.getStringExtra("uid");
        try {
            uid = Integer.parseInt(u);
        } catch (Exception e) {
            uid = -1;
        }
        int t = intent.getIntExtra("timeout", 60);
        timeout = t >= 5 ? t : 60;

        if (id == null || token == null || uid <= 0) {
            finish();
            return;
        }
        if (command == null) command = "";

        answering = false;
        deadline = System.currentTimeMillis() + timeout * 1000L;
        setContentView(buildUi());
        startTicker();
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Ui.CARD);
        Ui.pad(root, this, 22, 20, 22, 14);

        String label = "uid " + uid;
        Drawable icon = null;
        try {
            android.content.pm.PackageManager pm = getPackageManager();
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs != null && pkgs.length > 0) {
                android.content.pm.ApplicationInfo ai = pm.getApplicationInfo(pkgs[0], 0);
                label = String.valueOf(pm.getApplicationLabel(ai));
                icon = pm.getApplicationIcon(ai);
            }
        } catch (Exception ignored) {
        }

        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);

        ImageView iv = new ImageView(this);
        if (icon != null) {
            iv.setImageDrawable(icon);
        } else {
            iv.setImageDrawable(getPackageManager().getDefaultActivityIcon());
        }
        head.addView(iv, new LinearLayout.LayoutParams(Ui.dp(this, 48), Ui.dp(this, 48)));

        LinearLayout nameCol = new LinearLayout(this);
        nameCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams nlp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        nlp.leftMargin = Ui.dp(this, 14);
        head.addView(nameCol, nlp);

        TextView name = Ui.text(this, label, 18, Ui.TEXT);
        name.setSingleLine(true);
        name.setEllipsize(android.text.TextUtils.TruncateAt.END);
        nameCol.addView(name);

        TextView sub = Ui.text(this, "uid " + uid + " 正在请求 root 权限", 12, Ui.SUB);
        sub.setPadding(0, Ui.dp(this, 4), 0, 0);
        nameCol.addView(sub);

        root.addView(head);

        TextView cmdTitle = Ui.text(this, "要执行的命令", 12, Ui.SUB);
        cmdTitle.setPadding(0, Ui.dp(this, 18), 0, Ui.dp(this, 6));
        root.addView(cmdTitle);

        TextView cmd = Ui.text(this, command.length() == 0 ? "（交互式 shell）" : command,
                12, Ui.TEXT);
        cmd.setTypeface(android.graphics.Typeface.MONOSPACE);
        cmd.setBackground(Ui.round(this, 0xFFF5F6F8, 6, 0, 0));
        cmd.setPadding(Ui.dp(this, 12), Ui.dp(this, 10), Ui.dp(this, 12), Ui.dp(this, 10));
        cmd.setMaxLines(7);
        cmd.setEllipsize(android.text.TextUtils.TruncateAt.END);
        root.addView(cmd);

        remember = new CheckBox(this);
        remember.setText("记住我的选择（以后不再询问）");
        remember.setTextSize(13);
        remember.setTextColor(Ui.TEXT);
        remember.setChecked(true);
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        rlp.topMargin = Ui.dp(this, 14);
        root.addView(remember, rlp);

        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 46));
        blp.topMargin = Ui.dp(this, 16);
        root.addView(buttons, blp);

        Button deny = new Button(this);
        deny.setAllCaps(false);
        deny.setText("拒绝");
        deny.setTextSize(15);
        deny.setTextColor(Ui.RED);
        deny.setBackground(Ui.round(this, Ui.RED_LIGHT, 8, 0, 0));
        deny.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                submit("deny");
            }
        });
        LinearLayout.LayoutParams dlp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.MATCH_PARENT, 1f);
        dlp.rightMargin = Ui.dp(this, 6);
        buttons.addView(deny, dlp);

        Button allow = new Button(this);
        allow.setAllCaps(false);
        allow.setText("允许");
        allow.setTextSize(15);
        allow.setTextColor(0xFFFFFFFF);
        allow.setBackground(Ui.round(this, Ui.GREEN, 8, 0, 0));
        allow.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                submit("allow");
            }
        });
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.MATCH_PARENT, 1f);
        alp.leftMargin = Ui.dp(this, 6);
        buttons.addView(allow, alp);

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(timeout);
        progress.setProgress(timeout);
        LinearLayout.LayoutParams plp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 4));
        plp.topMargin = Ui.dp(this, 16);
        root.addView(progress, plp);

        countdown = Ui.text(this, timeout + " 秒后自动拒绝", 12, Ui.SUB);
        countdown.setGravity(Gravity.END);
        countdown.setPadding(0, Ui.dp(this, 6), 0, 0);
        root.addView(countdown);

        return root;
    }

    private void startTicker() {
        final int g = ++generation;
        ui.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (g != generation || answering) return;
                long left = deadline - System.currentTimeMillis();
                int sec = (int) Math.max(0, (left + 999) / 1000);
                if (countdown != null) {
                    countdown.setText(sec + " 秒后自动拒绝");
                }
                if (progress != null) {
                    progress.setProgress(sec);
                }
                if (left <= 0) {
                    submit("timeout");
                    return;
                }
                ui.postDelayed(this, 500);
            }
        }, 300);
    }

    private void submit(String decision) {
        if (answering) return;
        answering = true;

        boolean always = remember != null && remember.isChecked();
        final String dec;
        if ("timeout".equals(decision)) {
            dec = "deny";
        } else if ("allow".equals(decision)) {
            dec = always ? "allow_always" : "allow";
        } else {
            dec = always ? "deny_always" : "deny";
        }

        final String fid = id;
        final String ftok = token;
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    RootManager.answer(fid, ftok, dec);
                } catch (Exception ignored) {
                    /* 守护进程可能已经超时；不再打扰用户 */
                }
            }
        }).start();

        ui.postDelayed(new Runnable() {
            @Override
            public void run() {
                next();
            }
        }, 250);
    }

    private void next() {
        if (!pending.isEmpty()) {
            Intent in = pending.remove(0);
            bind(in);
        } else {
            finish();
        }
    }

    @Override
    public void onBackPressed() {
        submit("deny");
    }
}
