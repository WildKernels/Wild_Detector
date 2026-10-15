package com.wildkernels.lkmdetector;

import android.app.Activity;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Intent;
import android.content.res.Configuration;
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
 * Bear skin v2 over the LKM detection engine.
 * Look modeled on reveny/Android-Native-Root-Detector (MIT): verdict banner
 * directly under the title, flat rounded cards, expandable detection details.
 * Earlier skin was modeled on Duck-Detector-Refactoring (Apache-2.0).
 * Detections are entirely our own.
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

    private static final String REV_URL =
            "https://github.com/reveny/Android-Native-Root-Detector";
    private static final String DUCK_URL =
            "https://github.com/eltavine/Duck-Detector-Refactoring";

    private static final String[] PROBES = {
        "Placeholder scan", "mprotect/uaccess race", "Kernel taint flags",
        "Loaded modules", "kallsyms symbols", "O_PATH consistency", "Syscall timing",
    };

    private interface Probe { String run(); }

    /* palette (set per light/dark in onCreate) */
    private int BG, CARD, TEXT, TEXT2, POS, CRIT, CAUT, BTN, BTN_TXT;

    private ScrollView scroll;
    private Button btn;
    private LinearLayout bannerCard;
    private TextView bannerHead, bannerSub, statusLine;
    private TextView[] chips = new TextView[7];
    private TextView[] details = new TextView[7];
    private TextView[] chevs = new TextView[7];
    private String[] results = new String[7];
    private String[] labels = new String[7];
    private Handler ui;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ui = new Handler(Looper.getMainLooper());

        boolean dark = (getResources().getConfiguration().uiMode
                & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        if (dark) {
            BG = 0xFF141418; CARD = 0xFF232328; TEXT = 0xFFE6E1E5; TEXT2 = 0xFF9E9E9E;
            POS = 0xFF2E9E4F; CRIT = 0xFFE5533D; CAUT = 0xFFB26A00;
            BTN = 0xFFE6E1E5; BTN_TXT = 0xFF1C1B1F;
        } else {
            BG = 0xFFFAFAFA; CARD = 0xFFE8EEF1; TEXT = 0xFF1F1F1F; TEXT2 = 0xFF5F6368;
            POS = 0xFF1E8E3E; CRIT = 0xFFD93025; CAUT = 0xFFB26A00;
            BTN = 0xFF1F1F1F; BTN_TXT = 0xFFFFFFFF;
        }

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int m = (int) dp(16);
        content.setPadding(m, (int) dp(28), m, (int) dp(24));

        /* large title */
        TextView title = new TextView(this);
        title.setText("\uD83D\uDC3B LKM Detector");
        title.setTextSize(34f);
        title.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        title.setTextColor(TEXT);
        content.addView(title);
        String ver = "1.5";
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { }
        TextView subtitle = new TextView(this);
        subtitle.setText("v" + ver + " \u00B7 non-root susfs LKM detector");
        subtitle.setTextSize(13f);
        subtitle.setTextColor(TEXT2);
        subtitle.setPadding(0, (int) dp(4), 0, 0);
        content.addView(subtitle);

        /* verdict banner - fixed location, directly under the title */
        bannerCard = new LinearLayout(this);
        bannerCard.setOrientation(LinearLayout.VERTICAL);
        bannerCard.setBackground(rounded(POS, 24f));
        bannerCard.setPadding((int) dp(24), (int) dp(20), (int) dp(24), (int) dp(20));
        bannerCard.setVisibility(View.GONE);
        bannerHead = new TextView(this);
        bannerHead.setTextSize(20f);
        bannerHead.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        bannerHead.setTextColor(Color.WHITE);
        bannerCard.addView(bannerHead);
        bannerSub = new TextView(this);
        bannerSub.setTextSize(15f);
        bannerSub.setTextColor(Color.WHITE);
        bannerSub.setPadding(0, (int) dp(4), 0, 0);
        bannerCard.addView(bannerSub);
        LinearLayout.LayoutParams nlp = new LinearLayout.LayoutParams(-1, -2);
        nlp.topMargin = (int) dp(20);
        content.addView(bannerCard, nlp);

        /* RUN SCAN button */
        btn = new Button(this);
        btn.setText("RUN SCAN");
        btn.setAllCaps(false);
        btn.setTextSize(16f);
        btn.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        btn.setTextColor(BTN_TXT);
        btn.setBackground(rounded(BTN, 24f));
        btn.setPadding(0, (int) dp(14), 0, (int) dp(14));
        btn.setOnClickListener(v -> runScan());
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, -2);
        blp.topMargin = (int) dp(20);
        content.addView(btn, blp);

        /* status line */
        statusLine = new TextView(this);
        statusLine.setText("7 checks \u00B7 zero permissions \u00B7 zero root");
        statusLine.setTextSize(13f);
        statusLine.setTextColor(TEXT2);
        statusLine.setPadding(0, (int) dp(12), 0, 0);
        content.addView(statusLine);

        /* detection cards */
        for (int i = 0; i < PROBES.length; i++) {
            final int idx = i;
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setBackground(rounded(CARD, 24f));
            card.setPadding((int) dp(24), (int) dp(22), (int) dp(24), (int) dp(22));
            card.setOnClickListener(v -> toggleDetails(idx));

            LinearLayout head = new LinearLayout(this);
            head.setOrientation(LinearLayout.HORIZONTAL);
            head.setGravity(Gravity.CENTER_VERTICAL);
            TextView name = new TextView(this);
            name.setText(PROBES[i]);
            name.setTextSize(19f);
            name.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            name.setTextColor(TEXT);
            head.addView(name, new LinearLayout.LayoutParams(0, -2, 1f));
            TextView chev = new TextView(this);
            chev.setText("\u25BC");
            chev.setTextSize(14f);
            chev.setTextColor(TEXT2);
            chev.setVisibility(View.GONE);
            chevs[i] = chev;
            LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(-2, -2);
            clp.leftMargin = (int) dp(10);
            head.addView(chev, clp);
            TextView chip = makeChip();
            chips[i] = chip;
            head.addView(chip, chipLp());
            card.addView(head);

            TextView det = new TextView(this);
            det.setTextSize(15f);
            det.setTextColor(TEXT);
            det.setPadding(0, (int) dp(12), 0, 0);
            det.setVisibility(View.GONE);
            details[i] = det;
            card.addView(det);

            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.topMargin = (int) dp(16);
            content.addView(card, lp);
        }

        /* credits footer */
        TextView credit = new TextView(this);
        credit.setText("Design based on Native Detector (reveny, MIT) and, in earlier"
                + " versions, Duck Detector (Eltavine, Apache-2.0).\nDetections are our own."
                + "\nTap to open the Native Detector repo.");
        credit.setTextSize(11f);
        credit.setTextColor(TEXT2);
        credit.setPadding((int) dp(4), (int) dp(24), (int) dp(4), 0);
        credit.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(REV_URL)));
            } catch (Throwable t) {
                Toast.makeText(this, REV_URL, Toast.LENGTH_LONG).show();
            }
        });
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

    private LinearLayout.LayoutParams chipLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.leftMargin = (int) dp(10);
        return lp;
    }

    private TextView makeChip() {
        TextView p = new TextView(this);
        p.setTextSize(11f);
        p.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        p.setTextColor(Color.WHITE);
        p.setPadding((int) dp(12), (int) dp(4), (int) dp(12), (int) dp(4));
        p.setGravity(Gravity.CENTER);
        setChip(p, "IDLE", TEXT2);
        return p;
    }

    private void setChip(final TextView p, final String label, final int color) {
        ui.post(() -> {
            p.setText(label);
            p.setBackground(rounded(color, 999f));
        });
    }

    private void toggleDetails(int i) {
        if (details[i].getVisibility() != View.VISIBLE && details[i].getText().length() == 0)
            return;
        if (details[i].getVisibility() == View.VISIBLE) {
            details[i].setVisibility(View.GONE);
            chevs[i].setText("\u25BC");
        } else {
            details[i].setVisibility(View.VISIBLE);
            chevs[i].setText("\u25B2");
        }
    }

    /* ---------- scan ---------- */

    private void runScan() {
        btn.setEnabled(false);
        btn.setText("Scanning...");
        bannerCard.setVisibility(View.GONE);
        final Probe[] probes = {
            () -> nativeP1(), () -> nativeP2(10), () -> nativeP3(), () -> nativeP4(),
            () -> nativeP5(), () -> nativeP6(), () -> nativeP7(),
        };
        new Thread(() -> {
            int hits = 0, blocked = 0;
            try {
                for (int i = 0; i < probes.length; i++) {
                    final int fi = i;
                    setChip(chips[i], "...", CAUT);
                    ui.post(() -> statusLine.setText("Scanning P" + (fi + 1) + "/7 - " + PROBES[fi]));
                    String r;
                    try {
                        r = probes[i].run();
                    } catch (Throwable t) {
                        r = "!! native call failed: " + t + "\n";
                    }
                    Log.i("LKMDET", "[P" + (i + 1) + "]\n" + r);
                    results[i] = r;
                    boolean unreadable = r.contains("unreadable: Permission denied");
                    int hit = 0;
                    try { hit = nativeProbeResult(i + 1); } catch (Throwable ignored) { }
                    if (i == 6) {
                        labels[i] = "INFO";
                        setChip(chips[i], "INFO", TEXT2);
                    } else if (hit == 1) {
                        hits++;
                        labels[i] = "DETECTED";
                        setChip(chips[i], "DETECTED", CRIT);
                        final String d = hitLines(r);
                        ui.post(() -> {
                            details[fi].setText(d);
                            chevs[fi].setVisibility(View.VISIBLE);
                        });
                    } else if (unreadable) {
                        blocked++;
                        labels[i] = "N/A";
                        setChip(chips[i], "N/A", TEXT2);
                    } else {
                        labels[i] = "PASS";
                        setChip(chips[i], "PASS", POS);
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
                ui.post(() -> statusLine.setText("Scan crashed: " + t));
            } finally {
                ui.post(() -> {
                    btn.setEnabled(true);
                    btn.setText("RUN SCAN");
                });
            }
        }).start();
    }

    /** Pull the evidence lines (">>" markers) from a probe's output. */
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
        final String head, sub;
        final int color;
        switch (cls) {
            case 1:
                head = "DETECTED";
                sub = "susfs LKM on this device";
                color = CRIT;
                break;
            case 2:
                head = "DETECTED";
                sub = "built-in susfs symbols visible (fix defconfig)";
                color = CRIT;
                break;
            case 3:
                head = "DETECTED";
                sub = "unsigned out-of-tree module loaded (taint O/E)";
                color = CRIT;
                break;
            default:
                head = "PASS";
                sub = "no susfs LKM detected";
                color = POS;
                break;
        }
        Log.i("LKMDET", "verdict class " + cls + ": " + head + " - " + sub);
        ui.post(() -> {
            bannerHead.setText(head);
            bannerSub.setText(sub);
            bannerCard.setBackground(rounded(color, 24f));
            bannerCard.setAlpha(0f);
            bannerCard.setVisibility(View.VISIBLE);
            bannerCard.animate().alpha(1f).setDuration(250).start();
            int pass = 7 - hits - blocked - 1; /* minus P7 info */
            statusLine.setText(pass + " pass \u00B7 " + hits + " detected \u00B7 " + blocked + " blocked");
            scroll.post(() -> scroll.smoothScrollTo(0, 0));
        });
    }

    /* ---------- detections-only report to Downloads ---------- */

    private void saveLog(int cls) {
        StringBuilder sb = new StringBuilder();
        String ver = "1.5";
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { }
        sb.append("LKMDet v").append(ver)
          .append("  uid=").append(Process.myUid())
          .append("  kernel=").append(System.getProperty("os.version")).append('\n');
        sb.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date())).append('\n');
        switch (cls) {
            case 1: sb.append("\nDETECTED: susfs LKM on this device\n"); break;
            case 2: sb.append("\nDETECTED: built-in susfs symbols visible (fix defconfig)\n"); break;
            case 3: sb.append("\nDETECTED: unsigned out-of-tree module loaded (taint O/E)\n"); break;
            default: sb.append("\nPASS: no susfs LKM detected\n"); break;
        }
        boolean any = false;
        for (int i = 0; i < 7; i++) {
            if ("DETECTED".equals(labels[i]) && results[i] != null) {
                any = true;
                sb.append("\n[P").append(i + 1).append("] ").append(PROBES[i]).append(" - DETECTED\n");
                for (String line : results[i].split("\n")) {
                    String t = line.trim();
                    if (t.startsWith(">>")) sb.append("  ").append(t).append('\n');
                }
            }
        }
        if (!any) sb.append("\n(no detections)\n");
        sb.append("\nProbe summary: ");
        for (int i = 0; i < 7; i++) {
            if (i > 0) sb.append(" | ");
            sb.append("P").append(i + 1).append(" ").append(labels[i] == null ? "-" : labels[i]);
        }
        sb.append('\n');

        final String text = sb.toString();
        String where = null;
        Exception err = null;
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                Uri base = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
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
}
