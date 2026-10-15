package com.wildkernels.wilddetector.x;

import android.app.Activity;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.provider.MediaStore;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Wild Detector - X variant: all-new original design.
 * Gradient hero, big verdict circle, dot-status probe bars.
 * Engine identical to the other variants; detections are our own.
 */
public class MainActivity extends Activity {
    static { System.loadLibrary("lkmdet"); }

    private native String nativeP2(int seconds);
    private native String nativeP6();
    private native String nativeVerdict();
    private native int nativeFindings();
    private native int nativeProbeResult(int which);

    private static final String[] PROBES = {
        "mprotect/uaccess race", "O_PATH consistency",
    };
    private static final int[] PN = { 2, 6 };

    private interface Probe { String run(); }

    /* X palette (dark, blue accent) */
    private static final int BG     = 0xFF0B0E14;
    private static final int CARD   = 0xFF161B26;
    private static final int ACCENT = 0xFF5B8DEF;
    private static final int TEXT   = 0xFFEAEDF5;
    private static final int TEXT2  = 0xFF8A93A6;
    private static final int POS    = 0xFF3DD68C;
    private static final int CRIT   = 0xFFFF5C5C;
    private static final int EVID   = 0xFFFFB4B4;

    private ScrollView scroll;
    private Button btn;
    private LinearLayout verdictArea;
    private TextView circleGlyph, circleLabel, circleSub, statusLine;
    private TextView[] marks = new TextView[2];
    private View[] dots = new View[2];
    private TextView[] details = new TextView[2];
    private LinearLayout[] cards = new LinearLayout[2];
    private String[] results = new String[2];
    private String[] labels = new String[2];
    private Handler ui;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ui = new Handler(Looper.getMainLooper());

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int m = (int) dp(16);
        content.setPadding(m, 0, m, (int) dp(24));

        /* gradient hero */
        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable hbg = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{0xFF1B2C4A, 0xFF0B0E14});
        hbg.setCornerRadius(dp(24f));
        hero.setBackground(hbg);
        hero.setPadding((int) dp(24), (int) dp(32), (int) dp(24), (int) dp(24));

        TextView title = new TextView(this);
        title.setText("WILD DETECTOR");
        title.setTextSize(27f);
        title.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        title.setTextColor(TEXT);
        title.setLetterSpacing(0.08f);
        hero.addView(title);
        TextView subtitle = new TextView(this);
        subtitle.setText("X \u00B7 SUSFS LKM CHECK \u00B7 NON-ROOT");
        subtitle.setTextSize(11f);
        subtitle.setTypeface(Typeface.MONOSPACE);
        subtitle.setTextColor(TEXT2);
        subtitle.setLetterSpacing(0.2f);
        subtitle.setPadding(0, (int) dp(6), 0, 0);
        hero.addView(subtitle);

        /* verdict circle inside the hero */
        verdictArea = new LinearLayout(this);
        verdictArea.setOrientation(LinearLayout.VERTICAL);
        verdictArea.setGravity(Gravity.CENTER_HORIZONTAL);
        verdictArea.setPadding(0, (int) dp(24), 0, 0);
        verdictArea.setVisibility(View.GONE);
        circleGlyph = new TextView(this);
        circleGlyph.setText("\u2713");
        circleGlyph.setTextSize(46f);
        circleGlyph.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        circleGlyph.setTextColor(POS);
        circleGlyph.setGravity(Gravity.CENTER);
        GradientDrawable ring = new GradientDrawable();
        ring.setColor(0x00000000);
        ring.setCornerRadius(dp(60f));
        ring.setStroke((int) dp(3), POS);
        circleGlyph.setBackground(ring);
        verdictArea.addView(circleGlyph, new LinearLayout.LayoutParams((int) dp(120), (int) dp(120)));
        circleLabel = new TextView(this);
        circleLabel.setText("PASS");
        circleLabel.setTextSize(20f);
        circleLabel.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        circleLabel.setTextColor(POS);
        circleLabel.setLetterSpacing(0.15f);
        circleLabel.setPadding(0, (int) dp(12), 0, 0);
        verdictArea.addView(circleLabel);
        circleSub = new TextView(this);
        circleSub.setTextSize(13f);
        circleSub.setTextColor(TEXT2);
        circleSub.setPadding(0, (int) dp(2), 0, 0);
        verdictArea.addView(circleSub);
        hero.addView(verdictArea);
        content.addView(hero);

        /* SCAN NOW button */
        btn = new Button(this);
        btn.setText("SCAN NOW");
        btn.setAllCaps(false);
        btn.setTextSize(15f);
        btn.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        btn.setTextColor(Color.WHITE);
        btn.setLetterSpacing(0.08f);
        btn.setBackground(rounded(ACCENT, 999f));
        btn.setPadding(0, (int) dp(14), 0, (int) dp(14));
        btn.setOnClickListener(v -> runScan());
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, -2);
        blp.topMargin = (int) dp(16);
        content.addView(btn, blp);

        /* status line */
        statusLine = new TextView(this);
        statusLine.setText("2 CHECKS \u00B7 ZERO PERMISSIONS \u00B7 ZERO ROOT");
        statusLine.setTextSize(11f);
        statusLine.setTypeface(Typeface.MONOSPACE);
        statusLine.setTextColor(TEXT2);
        statusLine.setLetterSpacing(0.1f);
        statusLine.setPadding((int) dp(4), (int) dp(14), 0, 0);
        content.addView(statusLine);

        /* probe bars */
        for (int i = 0; i < PROBES.length; i++) {
            final int idx = i;
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setBackground(rounded(CARD, 18f));
            card.setPadding((int) dp(18), (int) dp(16), (int) dp(18), (int) dp(16));
            card.setOnClickListener(v -> toggleDetails(idx));

            LinearLayout head = new LinearLayout(this);
            head.setOrientation(LinearLayout.HORIZONTAL);
            head.setGravity(Gravity.CENTER_VERTICAL);
            View dot = new View(this);
            dot.setBackground(rounded(TEXT2, 999f));
            dots[i] = dot;
            head.addView(dot, new LinearLayout.LayoutParams((int) dp(10), (int) dp(10)));
            TextView name = new TextView(this);
            name.setText(PROBES[i]);
            name.setTextSize(15f);
            name.setTextColor(TEXT);
            LinearLayout.LayoutParams nlp2 = new LinearLayout.LayoutParams(0, -2, 1f);
            nlp2.leftMargin = (int) dp(12);
            head.addView(name, nlp2);
            TextView mark = new TextView(this);
            mark.setTextSize(12f);
            mark.setTypeface(Typeface.MONOSPACE);
            mark.setTypeface(Typeface.create(Typeface.MONOSPACE, Typeface.BOLD));
            mark.setTextColor(TEXT2);
            marks[i] = mark;
            head.addView(mark, lp(-2, -2, (int) dp(10)));
            card.addView(head);

            TextView det = new TextView(this);
            det.setTextSize(12f);
            det.setTypeface(Typeface.MONOSPACE);
            det.setTextColor(EVID);
            det.setPadding((int) dp(22), (int) dp(10), 0, 0);
            det.setVisibility(View.GONE);
            details[i] = det;
            card.addView(det);

            cards[i] = card;
            LinearLayout.LayoutParams clp2 = new LinearLayout.LayoutParams(-1, -2);
            clp2.topMargin = (int) dp(12);
            content.addView(card, clp2);
        }

        /* credits */
        TextView credit = new TextView(this);
        credit.setText("WILD DETECTOR X \u2014 original design \u00B7 engine ours"
                + "\nother looks: Native Detector (reveny, MIT) \u00B7 Duck Detector (Eltavine, Apache-2.0)");
        credit.setTextSize(10f);
        credit.setTypeface(Typeface.MONOSPACE);
        credit.setTextColor(TEXT2);
        credit.setPadding((int) dp(4), (int) dp(24), (int) dp(4), 0);
        content.addView(credit);

        scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);
        ScrollView.LayoutParams slp = new ScrollView.LayoutParams(-1, -2);
        content.setPadding(0, 0, 0, 0);
        scroll.addView(wrap(content), slp);
        setContentView(scroll);
    }

    /* hero sits edge-to-edge: pad content inside a wrapper instead */
    private LinearLayout wrap(LinearLayout inner) {
        LinearLayout w = new LinearLayout(this);
        w.setOrientation(LinearLayout.VERTICAL);
        int m = (int) dp(16);
        inner.setPadding(m, (int) dp(16), m, (int) dp(24));
        w.addView(inner);
        return w;
    }

    /* ---------- widgets ---------- */

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }

    private static LinearLayout.LayoutParams lp(int w, int h, int margin) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
        p.leftMargin = margin;
        return p;
    }

    private GradientDrawable rounded(int color, float rdp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(rdp));
        return g;
    }

    private void setDot(final int i, final int color) {
        ui.post(() -> dots[i].setBackground(rounded(color, 999f)));
    }

    private void setMark(final TextView p, final String label, final int color) {
        ui.post(() -> {
            p.setText(label);
            p.setTextColor(color);
        });
    }

    private void toggleDetails(int i) {
        if (details[i].getVisibility() != View.VISIBLE && details[i].getText().length() == 0)
            return;
        if (details[i].getVisibility() == View.VISIBLE)
            details[i].setVisibility(View.GONE);
        else
            details[i].setVisibility(View.VISIBLE);
    }

    /* ---------- scan ---------- */

    private void runScan() {
        btn.setEnabled(false);
        btn.setText("SCANNING...");
        verdictArea.setVisibility(View.GONE);
        for (int i = 0; i < 2; i++) {
            cards[i].setVisibility(View.VISIBLE);
            details[i].setText("");
            details[i].setVisibility(View.GONE);
            setDot(i, TEXT2);
            setMark(marks[i], "RUN", TEXT2);
        }
        final Probe[] probes = {
            () -> nativeP2(10), () -> nativeP6(),
        };
        new Thread(() -> {
            int hits = 0, blocked = 0;
            try {
                for (int i = 0; i < probes.length; i++) {
                    final int fi = i;
                    ui.post(() -> statusLine.setText("SCANNING " + (fi + 1) + "/" + PROBES.length + " \u00B7 " + PROBES[fi].toUpperCase(Locale.US)));
                    String r;
                    try {
                        r = probes[i].run();
                    } catch (Throwable t) {
                        r = "!! native call failed: " + t + "\n";
                    }
                    Log.i("LKMDET", "[P" + PN[i] + "]\n" + r);
                    results[i] = r;
                    int hit = 0;
                    try { hit = nativeProbeResult(PN[i]); } catch (Throwable ignored) { }
                    if (hit == 1) {
                        hits++;
                        labels[i] = "DETECTED";
                        setDot(i, CRIT);
                        setMark(marks[i], "HIT", CRIT);
                        final String d = hitLines(r);
                        ui.post(() -> details[fi].setText(d));
                    } else {
                        labels[i] = "PASS";
                        setDot(i, POS);
                        setMark(marks[i], "CLEAR", POS);
                    }
                }
                String v = null;
                try { v = nativeVerdict(); } catch (Throwable t) { Log.w("LKMDET", "verdict failed", t); }
                Log.i("LKMDET", v == null ? "(verdict failed)" : v);
                int cls = 0;
                try { cls = nativeFindings(); } catch (Throwable t) { Log.w("LKMDET", "findings failed", t); }
                showVerdict(cls, hits, blocked);
                saveLog(cls);
            } catch (Throwable t) {
                Log.e("LKMDET", "scan crashed", t);
                ui.post(() -> statusLine.setText("SCAN CRASHED: " + t));
            } finally {
                ui.post(() -> {
                    btn.setEnabled(true);
                    btn.setText("SCAN NOW");
                });
            }
        }).start();
    }

    private static String hitLines(String r) {
        StringBuilder sb = new StringBuilder();
        for (String line : r.split("\n")) {
            String t = line.trim();
            if (t.startsWith(">>")) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(t);
            }
        }
        return sb.toString();
    }

    private void showVerdict(final int cls, final int hits, final int blocked) {
        final String glyph, label, sub;
        final int color;
        if (cls != 0) {
            glyph = "\u2717";
            label = "DETECTED";
            sub = "susfs LKM on this device";
            color = CRIT;
        } else {
            glyph = "\u2713";
            label = "PASS";
            sub = "no susfs LKM detected";
            color = POS;
        }
        Log.i("LKMDET", "verdict class " + cls + ": " + label + " - " + sub);
        ui.post(() -> {
            circleGlyph.setText(glyph);
            circleGlyph.setTextColor(color);
            GradientDrawable ring = new GradientDrawable();
            ring.setColor(0x00000000);
            ring.setCornerRadius(dp(60f));
            ring.setStroke((int) dp(3), color);
            circleGlyph.setBackground(ring);
            circleLabel.setText(label);
            circleLabel.setTextColor(color);
            circleSub.setText(sub);
            verdictArea.setVisibility(View.VISIBLE);
            verdictArea.setAlpha(0f);
            verdictArea.animate().alpha(1f).setDuration(250).start();
            int pass = 2 - hits - blocked;
            statusLine.setText(pass + " CLEAR \u00B7 " + hits + " HIT \u00B7 " + blocked + " BLOCKED");
            for (int i = 0; i < 2; i++)
                if (!"DETECTED".equals(labels[i]))
                    cards[i].setVisibility(View.GONE);
            scroll.post(() -> scroll.smoothScrollTo(0, 0));
        });
    }

    /* ---------- detections-only report to Downloads ---------- */

    private void saveLog(int cls) {
        StringBuilder sb = new StringBuilder();
        String ver = "1.0";
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { }
        sb.append("Wild Detector X v").append(ver)
          .append("  uid=").append(Process.myUid())
          .append("  kernel=").append(System.getProperty("os.version")).append('\n');
        sb.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append('\n');
        if (cls != 0) sb.append("\nDETECTED: susfs LKM on this device\n");
        else sb.append("\nPASS: no susfs LKM detected\n");
        boolean any = false;
        for (int i = 0; i < 2; i++) {
            if ("DETECTED".equals(labels[i]) && results[i] != null) {
                any = true;
                sb.append("\n[P").append(PN[i]).append("] ").append(PROBES[i]).append(" - DETECTED\n");
                for (String line : results[i].split("\n")) {
                    String t = line.trim();
                    if (t.startsWith(">>")) sb.append("  ").append(t).append('\n');
                }
            }
        }
        if (!any) sb.append("\n(no detections)\n");

        final String text = sb.toString();
        String where = null;
        Exception err = null;
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                Uri base = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
                Cursor c = getContentResolver().query(base, null,
                        MediaStore.MediaColumns.DISPLAY_NAME + "=?",
                        new String[]{"wildetector_result.txt"}, null);
                if (c != null) {
                    while (c.moveToNext()) {
                        long id = c.getLong(c.getColumnIndex(MediaStore.MediaColumns._ID));
                        try {
                            getContentResolver().delete(ContentUris.withAppendedId(base, id), null, null);
                        } catch (SecurityException ignored) { }
                    }
                    c.close();
                }
                ContentValues cv = new ContentValues();
                cv.put(MediaStore.MediaColumns.DISPLAY_NAME, "wildetector_result.txt");
                cv.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                cv.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                Uri uri = getContentResolver().insert(base, cv);
                if (uri != null) {
                    OutputStream os = getContentResolver().openOutputStream(uri);
                    if (os != null) {
                        os.write(text.getBytes("UTF-8"));
                        os.close();
                        where = "Downloads/wildetector_result.txt";
                    }
                }
            } catch (Exception e) {
                err = e;
                Log.w("LKMDET", "mediastore save", e);
            }
        }
        if (where == null) {
            try {
                File dir = getExternalFilesDir(null);
                if (dir == null) dir = getFilesDir();
                File f = new File(dir, "wildetector_result.txt");
                FileWriter w = new FileWriter(f, false);
                w.write(text);
                w.close();
                where = f.getAbsolutePath();
            } catch (Exception e) {
                err = e;
                Log.w("LKMDET", "save failed", e);
            }
        }
        final String msg = where != null ? "Saved: " + where
                : "Log save failed" + (err != null ? " (" + err.getMessage() + ")" : "");
        Log.i("LKMDET", msg);
        ui.post(() -> Toast.makeText(this, msg, Toast.LENGTH_LONG).show());
    }
}
