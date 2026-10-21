package com.oldroot.manager;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

final class Ui {

    static final int BG = 0xFFF2F3F5;
    static final int CARD = 0xFFFFFFFF;
    static final int TEXT = 0xFF202124;
    static final int SUB = 0xFF6B7280;
    static final int GREEN = 0xFF2E7D32;
    static final int GREEN_LIGHT = 0xFFE6F4EA;
    static final int RED = 0xFFC62828;
    static final int RED_LIGHT = 0xFFFDECEA;
    static final int AMBER = 0xFFB26A00;
    static final int AMBER_LIGHT = 0xFFFFF4E0;
    static final int LINE = 0xFFE5E7EB;

    private Ui() {
    }

    static int dp(Context c, float v) {
        return (int) (v * c.getResources().getDisplayMetrics().density + 0.5f);
    }

    static TextView text(Context c, String s, float sp, int color) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        return t;
    }

    static GradientDrawable round(Context c, int fill, float radiusDp, int stroke, float strokeDp) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(dp(c, radiusDp));
        if (stroke != 0) {
            d.setStroke(Math.max(1, dp(c, strokeDp)), stroke);
        }
        return d;
    }

    static LinearLayout.LayoutParams lp(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    static void pad(View v, Context c, float l, float t, float r, float b) {
        v.setPadding(dp(c, l), dp(c, t), dp(c, r), dp(c, b));
    }

    static void margins(View v, Context c, float l, float t, float r, float b) {
        ViewGroup.LayoutParams lp = v.getLayoutParams();
        if (lp instanceof ViewGroup.MarginLayoutParams) {
            ((ViewGroup.MarginLayoutParams) lp).setMargins(dp(c, l), dp(c, t), dp(c, r), dp(c, b));
        }
    }

    static View divider(Context c) {
        View v = new View(c);
        v.setBackgroundColor(LINE);
        v.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 1));
        return v;
    }

    static TextView pill(Context c, String s, boolean good) {
        TextView t = text(c, s, 12, good ? GREEN : RED);
        t.setBackground(round(c, good ? GREEN_LIGHT : RED_LIGHT, 20, 0, 0));
        pad(t, c, 10, 3, 10, 3);
        return t;
    }

    static int color(int c) {
        return Color.argb(255, Color.red(c), Color.green(c), Color.blue(c));
    }
}
