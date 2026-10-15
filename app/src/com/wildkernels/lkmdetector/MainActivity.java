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
 * Wild Detector - detects the susfs4ksu-lkm loadable-module port.
 * X design, cleaned up in v2. Engine identical to the lkmdet CLI binary.
 */
public class MainActivity extends Activity {
    static { System.loadLibrary("lkmdet"); }

    private native String nativeP2(int seconds);
    private native String nativeP6();
    private native String nativeVerdict();
    private native int nativeFindings();
    private native int nativeProbeResult(int which);

    private static final String[] PROBES = {
        "getdents64 race leak", "O_PATH consistency",
    };
    private static final String[] DESC = {
        "Hidden /proc entry names leak out of the getdents64 buffer during an mprotect race",
        "/proc/susfs_* entries open fine but fstat says ENOENT - impossible on a clean kernel",
    };
    private static final int[] PN = { 2, 6 };

    private interface Probe { String run(); }

    /* palette */
    private static final int BG     = 0xFF0B0E14;
    private static final int CARD   = 0xFF161B26;
    private static final int ACCENT = 0xFF5B8DEF;
    private static final int TEXT   = 0xFFEAEDF5;
    private static final int TEXT2  = 0xFF8A93A6;
    private static final int POS    = 0xFF3DD68C;
    private static final int CRIT   = 0xFFFF5C5C;
    private static final int EVID   = 0xFFFFB4B4;

    private ScrollView scroll;
    private Button btn, saveBtn;
    private LinearLayout verdictArea;
    private TextView circleGlyph, circleLabel, circleSub, statusLine;
    private TextView[] marks = new TextView[2];
    private View[] dots = new View[2];
    private TextView[] details = new TextView[2];
    private LinearLayout[] cards = new LinearLayout[2];
    private String[] results = new String[2];
    private String[] labels = new String[2];
    private int lastCls = -1;
    private Handler ui;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ui = new Handler(Looper.getMainLooper());

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int m = (int) dp(16);
        content.setPadding(m, (int) dp(20), m, (int) dp(24));

        /* hero */
        LinearLayout hero = new LinearLayout(this);
        hero.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable hbg = new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{0xFF1B2C4A, 0xFF0B0E14});
        hbg.setCornerRadius(dp(24f));
        hero.setBackground(hbg);
        hero.setPadding((int) dp(24), (int) dp(28), (int) dp(24), (int) dp(24));

        TextView title = new TextView(this);
        title.setText("WILD DETECTOR");
        title.setTextSize(26f);
        title.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        title.setTextColor(TEXT);
        title.setLetterSpacing(0.06f);
        hero.addView(title);

        TextView detect = new TextView(this);
        detect.setText("Detects: susfs4ksu-lkm");
        detect.setTextSize(14f);
        detect.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        detect.setTextColor(ACCENT);
        detect.setPadding(0, (int) dp(12), 0, 0);
        hero.addView(detect);

        TextView detectSub = new TextView(this);
        detectSub.setText("the loadable-module port of susfs4ksu");
        detectSub.setTextSize(12f);
        detectSub.setTextColor(TEXT2);
        detectSub.setPadding(0, (int) dp(2), 0, 0);
        hero.addView(detectSub);

        /* verdict */
        verdictArea = new LinearLayout(this);
        verdictArea.setOrientation(LinearLayout.VERTICAL);
        verdictArea.setGravity(Gravity.CENTER_HORIZONTAL);
        verdictArea.setPadding(0, (int) dp(24), 0, 0);
        verdictArea.setVisibility(View.GONE);
        circleGlyph = new TextView(this);
        circleGlyph.setText("\u2713");
        circleGlyph.setTextSize(44f);
        circleGlyph.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        circleGlyph.setTextColor(POS);
        circleGlyph.setGravity(Gravity.CENTER);
        circleGlyph.setBackground(ring(POS));
        verdictArea.addView(circleGlyph, new LinearLayout.LayoutParams((int) dp(116), (int) dp(116)));
        circleLabel = new TextView(this);
        circleLabel.setText("PASS");
        circleLabel.setTextSize(19f);
        circleLabel.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        circleLabel.setTextColor(POS);
        circleLabel.setLetterSpacing(0.12f);
        circleLabel.setPadding(0, (int) dp(12), 0, 0);
        verdictArea.addView(circleLabel);
        circleSub = new TextView(this);
        circleSub.setTextSize(13f);
        circleSub.setTextColor(TEXT2);
        circleSub.setPadding(0, (int) dp(2), 0, 0);
        circleSub.setText("no susfs LKM detected");
        verdictArea.addView(circleSub);
        hero.addView(verdictArea);
        content.addView(hero);

        /* SCAN button */
        btn = new Button(this);
        btn.setText("SCAN NOW");
        btn.setAllCaps(false);
        btn.setTextSize(15f);
        btn.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        btn.setTextColor(Color.WHITE);
        btn.setLetterSpacing(0.06f);
        btn.setBackground(rounded(ACCENT, 999f));
        btn.setPadding(0, (int) dp(14), 0, (int) dp(14));
        btn.setOnClickListener(v -> runScan());
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, -2);
        blp.topMargin = (int) dp(16);
        content.addView(btn, blp);

        /* SAVE LOG button (appears after the first scan) */
        saveBtn = new Button(this);
        saveBtn.setText("SAVE LOG");
        saveBtn.setAllCaps(false);
        saveBtn.setTextSize(13f);
        saveBtn.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        saveBtn.setTextColor(ACCENT);
        saveBtn.setLetterSpacing(0.06f);
        GradientDrawable sd = new GradientDrawable();
        sd.setColor(0x00000000);
        sd.setCornerRadius(dp(999f));
        sd.setStroke((int) dp(2), ACCENT);
        saveBtn.setBackground(sd);
        saveBtn.setPadding(0, (int) dp(12), 0, (int) dp(12));
        saveBtn.setVisibility(View.GONE);
        saveBtn.setOnClickListener(v -> {
            if (lastCls < 0) {
                Toast.makeText(this, "Run a scan first", Toast.LENGTH_SHORT).show();
                return;
            }
            final int cls = lastCls;
            new Thread(() -> saveLog(cls)).start();
        });
        LinearLayout.LayoutParams slp2 = new LinearLayout.LayoutParams(-1, -2);
        slp2.topMargin = (int) dp(12);
        content.addView(saveBtn, slp2);

        /* status line */
        statusLine = new TextView(this);
        statusLine.setText("2 checks");
        statusLine.setTextSize(12f);
        statusLine.setTextColor(TEXT2);
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
            name.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            name.setTextColor(TEXT);
            LinearLayout.LayoutParams nlp = new LinearLayout.LayoutParams(0, -2, 1f);
            nlp.leftMargin = (int) dp(12);
            head.addView(name, nlp);
            TextView mark = new TextView(this);
            mark.setTextSize(12f);
            mark.setTypeface(Typeface.create(Typeface.MONOSPACE, Typeface.BOLD));
            mark.setTextColor(TEXT2);
            marks[i] = mark;
            LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(-2, -2);
            mlp.leftMargin = (int) dp(10);
            head.addView(mark, mlp);
            card.addView(head);

            TextView desc = new TextView(this);
            desc.setText(DESC[i]);
            desc.setTextSize(12f);
            desc.setTextColor(TEXT2);
            desc.setPadding((int) dp(22), (int) dp(6), 0, 0);
            card.addView(desc);

            TextView det = new TextView(this);
            det.setTextSize(12f);
            det.setTypeface(Typeface.MONOSPACE);
            det.setTextColor(EVID);
            det.setPadding((int) dp(22), (int) dp(8), 0, 0);
            det.setVisibility(View.GONE);
            details[i] = det;
            card.addView(det);

            cards[i] = card;
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(-1, -2);
            clp.topMargin = (int) dp(12);
            content.addView(card, clp);
        }

        /* credits */
        TextView credit = new TextView(this);
        credit.setText("engine: lkmdet \u00B7 design refs: Native Detector (reveny, MIT),"
                + " Duck Detector (Eltavine, Apache-2.0)");
        credit.setTextSize(10f);
        credit.setTypeface(Typeface.MONOSPACE);
        credit.setTextColor(TEXT2);
        credit.setPadding((int) dp(4), (int) dp(24), (int) dp(4), 0);
        content.addView(credit);

        scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFillViewport(true);
        scroll.addView(content, new ScrollView.LayoutParams(-1, -2));
        setContentView(scroll);
    }

    /* ---------- widgets ---------- */

    private float dp(float v) { return v * getResources().getDisplayMetrics().density; }

    private GradientDrawable rounded(int color, float rdp) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(rdp));
        return g;
    }

    private GradientDrawable ring(int color) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(0x00000000);
        g.setCornerRadius(dp(58f));
        g.setStroke((int) dp(3), color);
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
            setMark(marks[i], "...", TEXT2);
        }
        final Probe[] probes = {
            () -> nativeP2(10), () -> nativeP6(),
        };
        new Thread(() -> {
            int hits = 0;
            try {
                for (int i = 0; i < probes.length; i++) {
                    final int fi = i;
                    ui.post(() -> statusLine.setText("Scanning " + (fi + 1) + "/" + PROBES.length + " \u00B7 " + PROBES[fi]));
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
                showVerdict(cls, hits);
            } catch (Throwable t) {
                Log.e("LKMDET", "scan crashed", t);
                ui.post(() -> statusLine.setText("Scan crashed: " + t));
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

    private void showVerdict(final int cls, final int hits) {
        lastCls = cls;
        final String glyph, label, sub;
        final int color;
        if (cls != 0) {
            glyph = "\u2717";
            label = "DETECTED";
            sub = "susfs4ksu-lkm is on this device";
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
            circleGlyph.setBackground(ring(color));
            circleLabel.setText(label);
            circleLabel.setTextColor(color);
            circleSub.setText(sub);
            verdictArea.setVisibility(View.VISIBLE);
            verdictArea.setAlpha(0f);
            verdictArea.animate().alpha(1f).setDuration(250).start();
            statusLine.setText((2 - hits) + " clear \u00B7 " + hits + " hit");
            saveBtn.setVisibility(View.VISIBLE);
            for (int i = 0; i < 2; i++)
                if (!"DETECTED".equals(labels[i]))
                    cards[i].setVisibility(View.GONE);
            scroll.post(() -> scroll.smoothScrollTo(0, 0));
        });
    }

    /* ---------- on-demand report to Downloads ---------- */

    private void saveLog(int cls) {
        StringBuilder sb = new StringBuilder();
        String ver = "?";
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { }
        sb.append("Wild Detector v").append(ver)
          .append("  uid=").append(Process.myUid())
          .append("  kernel=").append(System.getProperty("os.version")).append('\n');
        sb.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append('\n');
        if (cls != 0) sb.append("\nDETECTED: susfs4ksu-lkm on this device\n");
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
