package com.oldroot.manager;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends Activity {

    private static final int MENU_REFRESH = 1;
    private static final int MENU_LOG = 2;
    private static final int MENU_SHELL = 3;
    private static final int MENU_ABOUT = 4;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ArrayList<AppEntry> entries = new ArrayList<AppEntry>();

    private ListView listView;
    private AppAdapter adapter;
    private TextView statusTitle;
    private TextView statusDetail;
    private TextView sectionTitle;
    private TextView emptyView;
    private View statusBar;
    private Button rootButton;
    private View statusCard;

    private AlertDialog progressDialog;
    private TextView progressText;

    private volatile boolean loading;
    private boolean running;

    static final class AppEntry {
        int uid;
        boolean allow;
        String label;
        String pkg;
        Drawable icon;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle("老机 Root");
        setContentView(buildUi());
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    // ---------------------------------------------------------------- UI 构建

    private View buildUi() {
        listView = new ListView(this);
        listView.setBackgroundColor(Ui.BG);
        listView.setDivider(new android.graphics.drawable.ColorDrawable(Ui.LINE));
        listView.setDividerHeight(1);
        listView.setCacheColorHint(0);

        listView.addHeaderView(buildStatusCard(), null, false);
        listView.addHeaderView(buildSectionHeader(), null, false);

        emptyView = Ui.text(this, "还没有应用申请过 Root\n\n安装需要 root 的应用后，\n它第一次执行 su 时会弹窗询问", 14, Ui.SUB);
        emptyView.setGravity(Gravity.CENTER);
        Ui.pad(emptyView, this, 32, 48, 32, 48);
        emptyView.setVisibility(View.GONE);
        listView.addFooterView(emptyView, null, false);

        adapter = new AppAdapter();
        listView.setAdapter(adapter);

        listView.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(android.widget.AdapterView<?> parent, View view, int position, long id) {
                int idx = position - listView.getHeaderViewsCount();
                if (idx >= 0 && idx < entries.size()) {
                    showEntryDialog(entries.get(idx));
                }
            }
        });
        return listView;
    }

    private View buildStatusCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(Ui.CARD);

        statusBar = new View(this);
        statusBar.setBackgroundColor(Ui.RED);
        card.addView(statusBar, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 3)));

        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        Ui.pad(body, this, 20, 16, 20, 18);
        card.addView(body);

        TextView caption = Ui.text(this, "ROOT 状态", 11, Ui.SUB);
        body.addView(caption);

        statusTitle = Ui.text(this, "检查中…", 24, Ui.TEXT);
        statusTitle.setPadding(0, Ui.dp(this, 6), 0, 0);
        body.addView(statusTitle);

        statusDetail = Ui.text(this, "", 13, Ui.SUB);
        statusDetail.setPadding(0, Ui.dp(this, 6), 0, 0);
        statusDetail.setLineSpacing(0, 1.15f);
        body.addView(statusDetail);

        rootButton = new Button(this);
        rootButton.setAllCaps(false);
        rootButton.setText("一键获取 Root");
        rootButton.setTextSize(15);
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, Ui.dp(this, 48));
        blp.topMargin = Ui.dp(this, 16);
        rootButton.setLayoutParams(blp);
        rootButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onRootButton();
            }
        });
        body.addView(rootButton);

        TextView hint = Ui.text(this, "临时 root：只对本次开机有效，重启自动恢复。\n"
                + "参考机型 小米 5 / Android 6 / 内核 3.18。", 12, Ui.SUB);
        hint.setPadding(0, Ui.dp(this, 12), 0, 0);
        hint.setLineSpacing(0, 1.2f);
        body.addView(hint);

        statusCard = card;
        return card;
    }

    private View buildSectionHeader() {
        LinearLayout h = new LinearLayout(this);
        h.setOrientation(LinearLayout.VERTICAL);
        Ui.pad(h, this, 20, 20, 20, 8);

        sectionTitle = Ui.text(this, "授权管理", 17, Ui.TEXT);
        h.addView(sectionTitle);

        TextView sub = Ui.text(this, "点一下可以改「允许 / 拒绝 / 删除记录」", 12, Ui.SUB);
        sub.setPadding(0, Ui.dp(this, 4), 0, 0);
        h.addView(sub);
        return h;
    }

    // ---------------------------------------------------------------- 数据

    private void refresh() {
        if (loading) return;
        loading = true;

        new Thread(new Runnable() {
            @Override
            public void run() {
                RootManager.Status st = null;
                final ArrayList<AppEntry> loaded = new ArrayList<AppEntry>();
                final String enforce = readSmall("/sys/fs/selinux/enforce");
                final String kernel = String.valueOf(System.getProperty("os.version"));
                boolean up = false;
                String err = null;
                try {
                    st = RootManager.status();
                    up = true;
                    List<RootManager.Entry> list = RootManager.list();
                    for (RootManager.Entry e : list) {
                        loaded.add(resolve(e));
                    }
                } catch (Throwable e) {
                    err = e.getClass().getSimpleName() + ": " + e.getMessage();
                    android.util.Log.e("RootMgr", "refresh failed", e);
                }
                final RootManager.Status status = st;
                final boolean fUp = up;
                final String fErr = err;
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        loading = false;
                        applyStatus(fUp, status, enforce, kernel, fErr);
                        entries.clear();
                        entries.addAll(loaded);
                        adapter.notifyDataSetChanged();
                        emptyView.setVisibility(loaded.isEmpty() ? View.VISIBLE : View.GONE);
                        sectionTitle.setText("授权管理" + (loaded.isEmpty() ? "" : " · " + loaded.size() + " 个应用"));
                    }
                });
            }
        }).start();
    }

    private AppEntry resolve(RootManager.Entry e) {
        AppEntry a = new AppEntry();
        a.uid = e.uid;
        a.allow = e.allow;
        String label = null;
        try {
            android.content.pm.PackageManager pm = getPackageManager();
            String[] pkgs = pm.getPackagesForUid(e.uid);
            if (pkgs != null && pkgs.length > 0) {
                a.pkg = pkgs[0];
                for (String p : pkgs) {
                    try {
                        android.content.pm.ApplicationInfo ai = pm.getApplicationInfo(p, 0);
                        if ((ai.flags & android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0) {
                            a.pkg = p;
                            break;
                        }
                    } catch (Exception ignored) {
                    }
                }
                android.content.pm.ApplicationInfo ai = pm.getApplicationInfo(a.pkg, 0);
                label = String.valueOf(pm.getApplicationLabel(ai));
                a.icon = pm.getApplicationIcon(ai);
            }
        } catch (Exception ignored) {
        }
        if (label == null || label.length() == 0) {
            a.label = "uid " + e.uid;
            a.pkg = a.pkg == null ? "" : a.pkg;
            a.icon = getPackageManager().getDefaultActivityIcon();
        } else {
            a.label = label;
        }
        return a;
    }

    private void applyStatus(boolean up, RootManager.Status status, String enforce, String kernel, String err) {
        running = up;
        boolean permissive = "0".equals(enforce);
        if (up) {
            statusBar.setBackgroundColor(Ui.GREEN);
            statusTitle.setText("已获取 Root");
            StringBuilder d = new StringBuilder();
            d.append("授权守护进程运行中");
            if (status != null) {
                d.append(" · SELinux ").append(permissive ? "Permissive" : "Enforcing");
                d.append(" · 弹窗超时 ").append(status.timeout).append(" 秒");
                if (status.managerUid > 0 && status.managerUid != android.os.Process.myUid()) {
                    d.append("\n注意：守护进程绑定的管理 App uid 与本机不一致（重装过？），请重新获取 Root。");
                }
            }
            statusDetail.setText(d.toString());
            rootButton.setText("Root 已就绪");
            rootButton.setEnabled(true);
        } else {
            statusBar.setBackgroundColor(permissive ? Ui.AMBER : Ui.RED);
            statusTitle.setText(permissive ? "Root 未完全就绪" : "未获取 Root");
            StringBuilder d = new StringBuilder();
            d.append("Android ").append(android.os.Build.VERSION.RELEASE);
            d.append(" · 内核 ").append(kernel);
            d.append("\nSELinux ").append(permissive ? "Permissive（已提权，但守护进程没起来）" : "Enforcing");
            if (err != null) {
                d.append("\n").append("守护进程：").append(err);
            }
            statusDetail.setText(d.toString());
            rootButton.setText("一键获取 Root");
            rootButton.setEnabled(true);
        }
    }

    // ---------------------------------------------------------------- 一键 root

    private void onRootButton() {
        if (running) {
            Toast.makeText(this, "Root 已经就绪，可以直接使用需要 root 的应用了", Toast.LENGTH_SHORT).show();
            return;
        }
        if (!RootInstaller.isArm64()) {
            new AlertDialog.Builder(this)
                    .setTitle("机型不支持")
                    .setMessage("这个临时 root 只支持 arm64 内核。\n当前 ABI：" + android.os.Build.CPU_ABI)
                    .setPositiveButton("知道了", null)
                    .show();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("一键获取 Root")
                .setMessage("会利用 CVE-2019-2215（binder UAF）拿到临时 root。\n\n"
                        + "· 只对本次开机有效，重启自动失效\n"
                        + "· 不写分区，但会把 SELinux 置为 Permissive\n"
                        + "· 内核 panic_on_oops=1 的机器上，失败有可能直接重启\n\n"
                        + "过程中请勿锁屏或切换应用。")
                .setPositiveButton("开始", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        startRoot();
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void startRoot() {
        showProgress("准备中…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                RootInstaller.run(MainActivity.this, new RootInstaller.Listener() {
                    @Override
                    public void onStep(final String message) {
                        ui.post(new Runnable() {
                            @Override
                            public void run() {
                                if (progressText != null) progressText.setText(message);
                            }
                        });
                    }

                    @Override
                    public void onDone(final RootInstaller.Result result) {
                        ui.post(new Runnable() {
                            @Override
                            public void run() {
                                dismissProgress();
                                showResult(result);
                            }
                        });
                    }
                });
            }
        }).start();
    }

    private void showProgress(String msg) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        Ui.pad(box, this, 24, 20, 24, 8);

        ProgressBar bar = new ProgressBar(this);
        bar.setIndeterminate(true);
        box.addView(bar);

        progressText = Ui.text(this, msg, 14, Ui.TEXT);
        progressText.setPadding(0, Ui.dp(this, 18), 0, 0);
        progressText.setLineSpacing(0, 1.2f);
        box.addView(progressText);

        progressDialog = new AlertDialog.Builder(this)
                .setTitle("获取 Root")
                .setView(box)
                .setCancelable(false)
                .create();
        progressDialog.show();
    }

    private void dismissProgress() {
        if (progressDialog != null) {
            try {
                progressDialog.dismiss();
            } catch (Exception ignored) {
            }
            progressDialog = null;
            progressText = null;
        }
    }

    private void showResult(RootInstaller.Result r) {
        if (r.ok) {
            new AlertDialog.Builder(this)
                    .setTitle(r.title)
                    .setMessage(r.detail)
                    .setPositiveButton("好", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            refresh();
                        }
                    })
                    .show();
        } else {
            showLongDialog(r.title, r.detail);
            refresh();
        }
    }

    private void showLongDialog(String title, String body) {
        ScrollView sc = new ScrollView(this);
        TextView tv = Ui.text(this, body, 12, Ui.TEXT);
        tv.setTextIsSelectable(true);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        Ui.pad(tv, this, 16, 12, 16, 12);
        sc.addView(tv);

        new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(sc)
                .setPositiveButton("知道了", null)
                .show();
    }

    // ---------------------------------------------------------------- 应用条目

    private void showEntryDialog(final AppEntry e) {
        String msg = "uid " + e.uid;
        if (e.pkg != null && e.pkg.length() > 0) msg += "\n" + e.pkg;
        msg += "\n\n当前：" + (e.allow ? "允许" : "拒绝");

        new AlertDialog.Builder(this)
                .setTitle(e.label)
                .setMessage(msg)
                .setPositiveButton(e.allow ? "改为拒绝" : "允许", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        setPolicy(e.uid, !e.allow);
                    }
                })
                .setNeutralButton("删除记录", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        removePolicy(e.uid);
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void setPolicy(final int uid, final boolean allow) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String err = null;
                try {
                    RootManager.setPolicy(uid, allow);
                } catch (Exception e) {
                    err = String.valueOf(e.getMessage());
                }
                final String fErr = err;
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        if (fErr != null) {
                            Toast.makeText(MainActivity.this, "修改失败：" + fErr, Toast.LENGTH_LONG).show();
                        } else {
                            Toast.makeText(MainActivity.this,
                                    allow ? "已允许" : "已拒绝", Toast.LENGTH_SHORT).show();
                        }
                        refresh();
                    }
                });
            }
        }).start();
    }

    private void removePolicy(final int uid) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String err = null;
                try {
                    RootManager.removePolicy(uid);
                } catch (Exception e) {
                    err = String.valueOf(e.getMessage());
                }
                final String fErr = err;
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        if (fErr != null) {
                            Toast.makeText(MainActivity.this, "删除失败：" + fErr, Toast.LENGTH_LONG).show();
                        }
                        refresh();
                    }
                });
            }
        }).start();
    }

    // ---------------------------------------------------------------- 菜单

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, MENU_REFRESH, 0, "刷新");
        menu.add(0, MENU_LOG, 1, "运行日志");
        menu.add(0, MENU_SHELL, 2, "以 root 执行命令");
        menu.add(0, MENU_ABOUT, 3, "关于");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case MENU_REFRESH:
                refresh();
                return true;
            case MENU_LOG:
                startActivity(new Intent(this, LogActivity.class));
                return true;
            case MENU_SHELL:
                shellDialog();
                return true;
            case MENU_ABOUT:
                aboutDialog();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void shellDialog() {
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setText("id");
        input.setSingleLine(false);
        input.setMinLines(2);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        Ui.pad(box, this, 24, 12, 24, 0);
        TextView tip = Ui.text(this, "以 uid 0 执行 /system/bin/sh -c：", 13, Ui.SUB);
        box.addView(tip);
        box.addView(input);

        new AlertDialog.Builder(this)
                .setTitle("执行 root 命令")
                .setView(box)
                .setPositiveButton("执行", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        runCommand(input.getText().toString());
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void runCommand(final String cmd) {
        if (cmd == null || cmd.trim().length() == 0) return;
        new Thread(new Runnable() {
            @Override
            public void run() {
                String text;
                try {
                    RootManager.ExecResult r = RootManager.exec(cmd);
                    text = r.denied ? "被拒绝：" + r.message
                            : r.output + "\n[退出码 " + r.code + "]";
                } catch (Exception e) {
                    text = "执行失败：" + e;
                }
                final String out = text;
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        showLongDialog("命令输出", out);
                    }
                });
            }
        }).start();
    }

    private void aboutDialog() {
        new AlertDialog.Builder(this)
                .setTitle("关于")
                .setMessage("老机 Root 1.0\n\n"
                        + "临时 root + 授权管理。基于 CVE-2019-2215。\n"
                        + "· su 客户端不依赖 setuid，交给全 capability 的守护进程执行\n"
                        + "· 授权记录保存在 /data/local/tmp/.su/policy.tsv\n"
                        + "· 日志 /data/local/tmp/.su/suvd.log\n\n"
                        + "关闭屏幕/重启后，SELinux 与 modprobe_path 都会恢复原样。")
                .setPositiveButton("知道了", null)
                .show();
    }

    // ---------------------------------------------------------------- 小工具

    private static String readSmall(String path) {
        FileInputStream in = null;
        try {
            in = new FileInputStream(path);
            byte[] b = new byte[128];
            int n = in.read(b);
            if (n <= 0) return "";
            return new String(b, 0, n).trim();
        } catch (Exception e) {
            return "";
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    // ---------------------------------------------------------------- 适配器

    private final class AppAdapter extends BaseAdapter {

        @Override
        public int getCount() {
            return entries.size();
        }

        @Override
        public Object getItem(int position) {
            return entries.get(position);
        }

        @Override
        public long getItemId(int position) {
            return entries.get(position).uid;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            LinearLayout row;
            if (convertView instanceof LinearLayout) {
                row = (LinearLayout) convertView;
            } else {
                row = new LinearLayout(MainActivity.this);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setBackgroundColor(Ui.CARD);
                Ui.pad(row, MainActivity.this, 16, 12, 16, 12);

                ImageView icon = new ImageView(MainActivity.this);
                LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(
                        Ui.dp(MainActivity.this, 44), Ui.dp(MainActivity.this, 44));
                row.addView(icon, ilp);

                LinearLayout col = new LinearLayout(MainActivity.this);
                col.setOrientation(LinearLayout.VERTICAL);
                LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(
                        0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
                clp.leftMargin = Ui.dp(MainActivity.this, 14);
                row.addView(col, clp);

                TextView name = Ui.text(MainActivity.this, "", 16, Ui.TEXT);
                col.addView(name);

                TextView detail = Ui.text(MainActivity.this, "", 12, Ui.SUB);
                detail.setPadding(0, Ui.dp(MainActivity.this, 3), 0, 0);
                col.addView(detail);

                TextView state = Ui.text(MainActivity.this, "", 12, Ui.GREEN);
                row.addView(state);
                row.setTag(new Object[]{icon, name, detail, state});
            }

            AppEntry e = entries.get(position);
            Object[] tags = (Object[]) row.getTag();
            ImageView icon = (ImageView) tags[0];
            TextView name = (TextView) tags[1];
            TextView detail = (TextView) tags[2];
            TextView state = (TextView) tags[3];

            icon.setImageDrawable(e.icon);
            name.setText(e.label);
            detail.setText("uid " + e.uid + (e.pkg == null || e.pkg.length() == 0 ? "" : " · " + e.pkg));
            state.setText(e.allow ? "允许" : "拒绝");
            state.setTextColor(e.allow ? Ui.GREEN : Ui.RED);
            state.setBackground(Ui.round(MainActivity.this,
                    e.allow ? Ui.GREEN_LIGHT : Ui.RED_LIGHT, 20, 0, 0));
            Ui.pad(state, MainActivity.this, 10, 3, 10, 3);
            return row;
        }
    }
}
