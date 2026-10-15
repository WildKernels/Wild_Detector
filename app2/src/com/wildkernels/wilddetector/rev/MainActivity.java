package com.wildkernels.wilddetector.rev;

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
 * Wild Detector - Rev variant.
 * Look modeled faithfully on reveny/Android-Native-Root-Detector (MIT):
 * white page, big title, status banner under the title, flat pale rounded
 * cards with triangle expanders. Detections are our own (susfs LKM engine).
 */
public class MainActivity extends Activity {
    static { System.loadLibrary("lkmdet"); }

    private native String nativeP2(int seconds);
    private native String nativeP6();
    private native String nativeVerdict();
    private native int nativeFindings();
    private native int nativeProbeResult(int which);

    private static final String REV_URL =
            "https://github.com/reveny/Android-Native-Root-Detector";

    private static final String[] PROBES = {
        "mprotect/uaccess race", "O_PATH consistency",
    };
    private static final int[] PN = { 2, 6 };

    private interface Probe { String run(); }

    /* reveny palette (light, forced) */
    private static final int BG      = 0xFFFAFAFA;
    private static final int CARD    = 0xFFE8EEF1;
    private static final int TEXT    = 0xFF1F1F1F;
    private static final int TEXT2   = 0xFF5F6368;
    private static final int POS     = 0xFF1E8E3E;
    private static final int CRIT    = 0xFFD93025;
    private static final int BTN     = 0xFF1F1F1F;
    private static final int BTN_TXT = 0xFFFFFFFF;

    private ScrollView scroll;
    private Button btn;
    private LinearLayout bannerCard;
    private TextView bannerHead, bannerSub, statusLine;
    private TextView[] marks = new TextView[2];
    private TextView[] chevs = new TextView[2];
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
        content.setPadding(m, (int) dp(28), m, (int) dp(24));

        /* big title */
        TextView title = new TextView(this);
        title.setText("Wild Detector");
        title.setTextSize(36f);
        title.setTextColor(TEXT);
        content.addView(title);
        TextView subtitle = new TextView(this);
        subtitle.setText("Rev \u00B7 non-root susfs LKM detector \u00B7 zero permissions");
        subtitle.setTextSize(13f);
        subtitle.setTextColor(TEXT2);
        subtitle.setPadding(0, (int) dp(4), 0, 0);
        content.addView(subtitle);

        /* status banner - fixed under the title */
        bannerCard = new LinearLayout(this);
        bannerCard.setOrientation(LinearLayout.VERTICAL);
        bannerCard.setBackground(rounded(POS, 26f));
        bannerCard.setPadding((int) dp(24), (int) dp(20), (int) dp(24), (int) dp(20));
        bannerCard.setVisibility(View.GONE);
        bannerHead = new TextView(this);
        bannerHead.setTextSize(21f);
        bannerHead.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        bannerHead.setTextColor(Color.WHITE);
        bannerCard.addView(bannerHead);
        bannerSub = new TextView(this);
        bannerSub.setTextSize(16f);
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
        btn.setBackground(rounded(BTN, 26f));
        btn.setPadding(0, (int) dp(14), 0, (int) dp(14));
        btn.setOnClickListener(v -> runScan());
        LinearLayout.LayoutParams blp = new LinearLayout.LayoutParams(-1, -2);
        blp.topMargin = (int) dp(20);
        content.addView(btn, blp);

        /* status line */
        statusLine = new TextView(this);
        statusLine.setText("2 checks \u00B7 zero permissions \u00B7 zero root");
        statusLine.setTextSize(13f);
        statusLine.setTextColor(TEXT2);
        statusLine.setPadding(0, (int) dp(12), 0, 0);
        content.addView(statusLine);

        /* detection cards */
        for (int i = 0; i < PROBES.length; i++) {
            final int idx = i;
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setBackground(rounded(CARD, 26f));
            card.setPadding((int) dp(24), (int) dp(22), (int) dp(24), (int) dp(22));
            card.setOnClickListener(v -> toggleDetails(idx));

            LinearLayout head = new LinearLayout(this);
            head.setOrientation(LinearLayout.HORIZONTAL);
            head.setGravity(Gravity.CENTER_VERTICAL);
            TextView name = new TextView(this);
            name.setText(PROBES[i]);
            name.setTextSize(20f);
            name.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            name.setTextColor(TEXT);
            head.addView(name, new LinearLayout.LayoutParams(0, -2, 1f));
            TextView mark = new TextView(this);
            mark.setTextSize(14f);
            mark.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            mark.setTextColor(TEXT);
            mark.setVisibility(View.GONE);
            marks[i] = mark;
            head.addView(mark, lp(-2, -2, (int) dp(10)));
            TextView chev = new TextView(this);
            chev.setText("\u25BC");
            chev.setTextSize(14f);
            chev.setTextColor(TEXT);
            chev.setVisibility(View.GONE);
            chevs[i] = chev;
            head.addView(chev, lp(-2, -2, (int) dp(6)));
            card.addView(head);

            TextView det = new TextView(this);
            det.setTextSize(16f);
            det.setTextColor(TEXT);
            det.setPadding(0, (int) dp(12), 0, 0);
            det.setVisibility(View.GONE);
            details[i] = det;
            card.addView(det);

            cards[i] = card;
            LinearLayout.LayoutParams clp2 = new LinearLayout.LayoutParams(-1, -2);
            clp2.topMargin = (int) dp(16);
            content.addView(card, clp2);
        }

        /* credits */
        TextView credit = new TextView(this);
        credit.setText("Design based on Native Detector (reveny, MIT) \u2014 detections are our own."
                + "\nTap to open the repo.");
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

    private void setMark(final TextView p, final String label, final int color) {
        ui.post(() -> {
            p.setText(label);
            p.setTextColor(color);
            p.setVisibility(View.VISIBLE);
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
        for (int i = 0; i < 2; i++) {
            cards[i].setVisibility(View.VISIBLE);
            details[i].setText("");
            details[i].setVisibility(View.GONE);
            chevs[i].setVisibility(View.GONE);
            chevs[i].setText("\u25BC");
            marks[i].setVisibility(View.GONE);
        }
        final Probe[] probes = {
            () -> nativeP2(10), () -> nativeP6(),
        };
        new Thread(() -> {
            int hits = 0, blocked = 0;
            try {
                for (int i = 0; i < probes.length; i++) {
                    final int fi = i;
                    setMark(marks[i], "...", TEXT2);
                    ui.post(() -> statusLine.setText("Scanning " + (fi + 1) + "/" + PROBES.length + " - " + PROBES[fi]));
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
                        setMark(marks[i], "\u2717 DETECTED", CRIT);
                        final String d = "Details:\n" + hitLines(r);
                        ui.post(() -> {
                            details[fi].setText(d);
                            chevs[fi].setVisibility(View.VISIBLE);
                        });
                    } else {
                        labels[i] = "PASS";
                        setMark(marks[i], "\u2713", POS);
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
        if (cls != 0) {
            head = "DETECTED";
            sub = "susfs LKM on this device";
            color = CRIT;
        } else {
            head = "PASS";
            sub = "no susfs LKM detected";
            color = POS;
        }
        Log.i("LKMDET", "verdict class " + cls + ": " + head + " - " + sub);
        ui.post(() -> {
            bannerHead.setText(head);
            bannerSub.setText(sub);
            bannerCard.setBackground(rounded(color, 26f));
            bannerCard.setAlpha(0f);
            bannerCard.setVisibility(View.VISIBLE);
            bannerCard.animate().alpha(1f).setDuration(250).start();
            int pass = 2 - hits - blocked;
            statusLine.setText(pass + " pass \u00B7 " + hits + " detected \u00B7 " + blocked + " blocked");
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
        sb.append("Wild Detector Rev v").append(ver)
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
