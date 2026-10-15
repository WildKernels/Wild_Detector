package com.wildkernels.lkmdetector;

import android.app.Activity;
import android.content.ContentUris;
import android.content.ContentValues;
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
 * Duck-style (iOS grouped dark) skin over the LKM detection engine.
 * Look modeled on eltavine/Duck-Detector-Refactoring (Apache-2.0) design tokens;
 * detections are entirely our own.
 */
public class MainActivity extends Activity {
    static { System.loadLibrary("lkmdet"); }

    private native String nativeBanner();
    private native String nativeP1();
    private native String nativeP2(int seconds);
    private native String nativeP3();
    private native String nativeP4();
    private native String nativeP5();
    private native String nativeP6();
    private native String nativeP7();
    private native String nativeVerdict();
    private native int nativeFindings();
    private native int nativeProbeResult(int which);

    /* ---- Duck palette (dark) ---- */
    private static final int PAGE    = 0xFF000000;
    private static final int CARD    = 0xFF1C1C1E;
    private static final int INSET   = 0xFF2C2C2E;
    private static final int HAIRLINE = 0x8C38383A;
    private static final int TEXT    = 0xFFFFFFFF;
    private static final int TEXT2   = 0xFF98989F;
    private static final int POS     = 0xFF36D167;
    private static final int CAUT    = 0xFFF5A623;
    private static final int CRIT    = 0xFFFF453A;
    private static final int NEUT    = 0xFF98989D;
    private static final int BTN     = 0xFFE5E5EA;
    private static final int BTN_TXT = 0xFF1C1C1E;

    private static final String[] PROBES = {
        "Placeholder scan", "mprotect/uaccess race", "Kernel taint flags",
        "Loaded modules", "kallsyms symbols", "O_PATH consistency", "Syscall timing",
    };
    private static final String[] DESC = {
        "getdents64(/proc) entries with zero inode",
        "10s race window on getdents64 while flipping PTE permissions",
        "/proc/sys/kernel/tainted O (out-of-tree) and E (unsigned)",
        "/proc/modules scanned for susfs strings",
        "/proc/kallsyms scanned for susfs symbol leaks",
        "O_PATH open + fstat vs path-based check on /proc/susfs_*",
        "syscall latency medians (informational only)",
    };

    private interface Probe { String run(); }

    private TextView log;
    private ScrollView scroll;
    private Button btn;
    private TextView banner;
    private TextView[] pills = new TextView[7];
    private Handler ui;
    private final StringBuilder fullLog = new StringBuilder();

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ui = new Handler(Looper.getMainLooper());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(PAGE);

        /* ---- scrollable dashboard ---- */
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int m = (int) dp(16);
        content.setPadding(m, (int) dp(20), m, (int) dp(24));

        /* large title */
        TextView title = new TextView(this);
        title.setText("\uD83E\uDD86 LKM Detector");
        title.setTextSize(34f);
        title.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        title.setTextColor(TEXT);
        title.setLetterSpacing(-0.015f);
        content.addView(title);
        TextView subtitle = new TextView(this);
        subtitle.setText("v1.3 \u00B7 non-root susfs LKM detector \u00B7 zero permissions");
        subtitle.setTextSize(12f);
        subtitle.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        subtitle.setTextColor(TEXT2);
        subtitle.setPadding(0, (int) dp(4), 0, 0);
        content.addView(subtitle);

        /* DEVICE info card */
        content.addView(sectionLabel("DEVICE"));
        LinearLayout info = card(16f);
        infoRow(info, "Kernel", System.getProperty("os.version"));
        infoRow(info, "Device", Build.MODEL + " \u00B7 Android " + Build.VERSION.RELEASE
                + " (SDK " + Build.VERSION.SDK_INT + ")");
        int uid = Process.myUid();
        infoRow(info, "UID", "u0_a" + (uid - 10000) + "  (" + uid + ")");
        infoRow(info, "Started", new SimpleDateFormat("MMM d, HH:mm:ss", Locale.US).format(new Date()));
        content.addView(info);

        /* DETECTORS card */
        content.addView(sectionLabel("DETECTORS"));
        LinearLayout det = card(16f);
        for (int i = 0; i < PROBES.length; i++) {
            if (i > 0) det.addView(hairline());
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(m, (int) dp(12), m, (int) dp(12));
            LinearLayout top = new LinearLayout(this);
            top.setOrientation(LinearLayout.HORIZONTAL);
            top.setGravity(Gravity.CENTER_VERTICAL);
            TextView name = new TextView(this);
            name.setText(PROBES[i]);
            name.setTextSize(17f);
            name.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            name.setTextColor(TEXT);
            top.addView(name, new LinearLayout.LayoutParams(0, -2, 1f));
            TextView pill = makePill();
            pills[i] = pill;
            LinearLayout.LayoutParams plp = new LinearLayout.LayoutParams(-2, -2);
            plp.leftMargin = (int) dp(8);
            top.addView(pill, plp);
            row.addView(top);
            TextView desc = new TextView(this);
            desc.setText(DESC[i]);
            desc.setTextSize(13f);
            desc.setTextColor(TEXT2);
            desc.setPadding(0, (int) dp(2), 0, 0);
            row.addView(desc);
            det.addView(row);
        }
        content.addView(det);

        /* SCAN LOG card */
        content.addView(sectionLabel("SCAN LOG"));
        LinearLayout logCard = card(12f);
        logCard.setBackgroundColor(INSET);
        log = new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(11f);
        log.setTextColor(0xFFE5E5EA);
        log.setPadding(m, (int) dp(12), m, (int) dp(12));
        log.setTextIsSelectable(true);
        logCard.addView(log);
        content.addView(logCard);

        /* RUN SCAN button */
        btn = new Button(this);
        btn.setText("RUN SCAN");
        btn.setAllCaps(false);
        btn.setTextSize(17f);
        btn.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        btn.setTextColor(BTN_TXT);
        btn.setBackground(rounded(BTN, 20f));
        btn.setPadding((int) dp(20), (int) dp(14), (int) dp(20), (int) dp(14));
        btn.setOnClickListener(v -> runScan());
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, -2);
        blp.topMargin = (int) dp(24);
        content.addView(btn, blp);

        scroll = new ScrollView(this);
        scroll.setBackgroundColor(PAGE);
        scroll.setFillViewport(true);
        scroll.addView(content, new ScrollView.LayoutParams(-1, -2));
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1f));

        /* bottom verdict banner (tap to dismiss) */
        banner = new TextView(this);
        banner.setTextSize(16f);
        banner.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        banner.setTextColor(Color.WHITE);
        banner.setGravity(Gravity.CENTER);
        banner.setPadding(0, (int) dp(18), 0, (int) dp(18));
        GradientDrawable bgd = new GradientDrawable();
        bgd.setColor(POS);
        bgd.setCornerRadii(new float[]{dp(20), dp(20), dp(20), dp(20), 0, 0, 0, 0});
        banner.setBackground(bgd);
        banner.setVisibility(View.GONE);
        banner.setOnClickListener(v -> banner.setVisibility(View.GONE));
        root.addView(banner, new LinearLayout.LayoutParams(-1, -2));

        setContentView(root);

        append("LKMDet " + callSafe("banner") + "\n\n");
        append("Probes: placeholder / mprotect-race / taint / modules /\n");
        append("        kallsyms / O_PATH / timing. Zero permissions, zero root.\n");
        append("Tap RUN SCAN - result pops at the bottom, log saves to Downloads.\n\n");
    }

    /* ---------- duck-style widgets ---------- */

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }

    private GradientDrawable rounded(int color, float rdp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(rdp));
        return g;
    }

    private TextView sectionLabel(String s) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(12f);
        t.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        t.setTextColor(TEXT2);
        t.setPadding((int) dp(4), (int) dp(20), 0, (int) dp(8));
        return t;
    }

    private LinearLayout card(float rdp) {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackground(rounded(CARD, rdp));
        return c;
    }

    private View hairline() {
        View v = new View(this);
        v.setBackgroundColor(HAIRLINE);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, Math.max(1, (int) dp(0.5f)));
        lp.leftMargin = (int) dp(16);
        v.setLayoutParams(lp);
        return v;
    }

    private TextView makePill() {
        TextView p = new TextView(this);
        p.setTextSize(11f);
        p.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        p.setTextColor(Color.WHITE);
        p.setPadding((int) dp(10), (int) dp(3), (int) dp(10), (int) dp(3));
        p.setGravity(Gravity.CENTER);
        setPill(p, "IDLE", NEUT);
        return p;
    }

    private void setPill(final TextView p, final String label, final int color) {
        ui.post(() -> {
            p.setText(label);
            p.setBackground(rounded(color, 999f));
        });
    }

    private void infoRow(LinearLayout card, String label, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding((int) dp(16), (int) dp(11), (int) dp(16), (int) dp(11));
        TextView l = new TextView(this);
        l.setText(label);
        l.setTextSize(13f);
        l.setTextColor(TEXT2);
        row.addView(l, new LinearLayout.LayoutParams(0, -2, 1f));
        TextView v = new TextView(this);
        v.setText(value);
        v.setTextSize(13f);
        v.setTextColor(TEXT);
        row.addView(v, new LinearLayout.LayoutParams(-2, -2));
        card.addView(row);
    }

    /* ---------- scan ---------- */

    private String callSafe(String what) {
        try {
            return nativeBanner();
        } catch (Throwable t) {
            return "!! native (" + what + ") failed: " + t;
        }
    }

    private void runScan() {
        btn.setEnabled(false);
        btn.setText("Scanning...");
        btn.setTextColor(TEXT2);
        banner.setVisibility(View.GONE);
        final Probe[] probes = {
            () -> nativeP1(), () -> nativeP2(10), () -> nativeP3(), () -> nativeP4(),
            () -> nativeP5(), () -> nativeP6(), () -> nativeP7(),
        };
        new Thread(() -> {
            try {
                for (int i = 0; i < probes.length; i++) {
                    setPill(pills[i], "SCANNING", CAUT);
                    post("\n[P" + (i + 1) + "] " + PROBES[i] + "\n");
                    String r;
                    try {
                        r = probes[i].run();
                    } catch (Throwable t) {
                        r = "  !! native call failed: " + t + "\n";
                    }
                    Log.i("LKMDET", "[P" + (i + 1) + "]\n" + r);
                    post(r);
                    int hit = 0;
                    try { hit = nativeProbeResult(i + 1); } catch (Throwable ignored) { }
                    if (i == 6) setPill(pills[i], "INFO", NEUT);
                    else setPill(pills[i], hit == 1 ? "HIT" : "CLEAN", hit == 1 ? CRIT : POS);
                }
                post("\n=== VERDICT ===\n");
                String v = nativeVerdict();
                Log.i("LKMDET", v);
                post(v + "\n");
                int cls = 0;
                try { cls = nativeFindings(); } catch (Throwable t) { Log.w("LKMDET", "findings failed", t); }
                showVerdict(cls);
                saveLog();
            } catch (Throwable t) {
                post("\n!! scan crashed: " + t + "\n");
            } finally {
                ui.post(() -> {
                    btn.setEnabled(true);
                    btn.setText("RUN SCAN");
                    btn.setTextColor(BTN_TXT);
                });
            }
        }).start();
    }

    private void showVerdict(final int cls) {
        final String text;
        final int color;
        switch (cls) {
            case 1:
                text = "DETECTED - susfs LKM on this device";
                color = CRIT;
                break;
            case 2:
                text = "DETECTED - built-in susfs symbols visible (fix defconfig)";
                color = CRIT;
                break;
            case 3:
                text = "DETECTED - unsigned out-of-tree module loaded (taint O/E)";
                color = CRIT;
                break;
            default:
                text = "PASS - no susfs LKM detected";
                color = POS;
                break;
        }
        Log.i("LKMDET", "verdict class " + cls + ": " + text);
        ui.post(() -> {
            banner.setText(text);
            GradientDrawable g = new GradientDrawable();
            g.setColor(color);
            g.setCornerRadii(new float[]{dp(20), dp(20), dp(20), dp(20), 0, 0, 0, 0});
            banner.setBackground(g);
            banner.setAlpha(0f);
            banner.setVisibility(View.VISIBLE);
            banner.animate().alpha(1f).setDuration(250).start();
        });
    }

    /* ---------- log capture + Downloads ---------- */

    private void saveLog() {
        final String text = fullLog.toString();
        String where = null;
        Exception err = null;
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                Uri base = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
                /* replace our previous copy so the file stays lkmdet_result.txt */
                Cursor c = getContentResolver().query(base, null,
                        MediaStore.MediaColumns.DISPLAY_NAME + "=?",
                        new String[]{"lkmdet_result.txt"}, null);
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
                cv.put(MediaStore.MediaColumns.DISPLAY_NAME, "lkmdet_result.txt");
                cv.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                cv.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                Uri uri = getContentResolver().insert(base, cv);
                if (uri != null) {
                    OutputStream os = getContentResolver().openOutputStream(uri);
                    if (os != null) {
                        os.write(text.getBytes("UTF-8"));
                        os.close();
                        where = "Downloads/lkmdet_result.txt";
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
                File f = new File(dir, "lkmdet_result.txt");
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

    private void post(final String s) {
        ui.post(() -> append(s));
    }

    private synchronized void append(String s) {
        fullLog.append(s);
        log.append(s);
        scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
    }
}
