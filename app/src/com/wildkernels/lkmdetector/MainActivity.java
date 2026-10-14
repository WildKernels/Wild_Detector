package com.wildkernels.lkmdetector;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
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

    private interface Probe { String run(); }

    private TextView log;
    private ScrollView scroll;
    private Button btn;
    private TextView banner;
    private Handler ui;
    private final StringBuilder fullLog = new StringBuilder();

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        ui = new Handler(Looper.getMainLooper());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);

        btn = new Button(this);
        btn.setText("RUN SCAN");
        btn.setAllCaps(false);

        log = new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(12f);
        log.setTextColor(Color.parseColor("#CCFFCC"));
        log.setPadding(24, 16, 24, 32);
        log.setTextIsSelectable(true);

        scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#101010"));
        scroll.addView(log);

        banner = new TextView(this);
        banner.setTextSize(17f);
        banner.setTypeface(Typeface.DEFAULT_BOLD);
        banner.setTextColor(Color.WHITE);
        banner.setGravity(Gravity.CENTER);
        banner.setPadding(24, 30, 24, 30);
        banner.setVisibility(View.GONE);
        banner.setOnClickListener(v -> banner.setVisibility(View.GONE));

        btn.setOnClickListener(v -> runScan());
        root.addView(btn);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        root.addView(banner, new LinearLayout.LayoutParams(-1, -2));
        setContentView(root);

        append("LKMDet - non-root susfs LKM detector\n\n");
        append(callSafe("banner") + "\n");
        append("Probes: placeholder / mprotect-race / taint / modules /\n");
        append("        kallsyms / O_PATH / timing. Zero permissions, zero root.\n");
        append("The race probe runs ~10s. Tap RUN SCAN.\n");
        append("Result appears as a PASS/DETECTED bar at the bottom (tap to hide).\n\n");
    }

    private String callSafe(String what) {
        try {
            return nativeBanner();
        } catch (Throwable t) {
            return "!! native (" + what + ") failed: " + t;
        }
    }

    private void runScan() {
        btn.setEnabled(false);
        btn.setText("scanning...");
        banner.setVisibility(View.GONE);
        new Thread(() -> {
            try {
                step("[P1] placeholder scan (raw getdents64, zero-ino)", () -> nativeP1());
                step("[P2] mprotect/uaccess race on getdents64(/proc) - 10s", () -> nativeP2(10));
                step("[P3] /proc/sys/kernel/tainted", () -> nativeP3());
                step("[P4] /proc/modules grep", () -> nativeP4());
                step("[P5] /proc/kallsyms symbol grep", () -> nativeP5());
                step("[P6] O_PATH/fstat consistency on /proc/susfs_*", () -> nativeP6());
                step("[P7] syscall latency medians (INFO)", () -> nativeP7());
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
                ui.post(() -> { btn.setEnabled(true); btn.setText("RUN SCAN"); });
            }
        }).start();
    }

    private void showVerdict(final int cls) {
        final String text;
        final int color;
        switch (cls) {
            case 1:
                text = "DETECTED - susfs LKM on this device";
                color = Color.parseColor("#C62828");
                break;
            case 2:
                text = "DETECTED - built-in susfs symbols visible (fix defconfig)";
                color = Color.parseColor("#C62828");
                break;
            case 3:
                text = "DETECTED - unsigned out-of-tree module loaded (taint O/E)";
                color = Color.parseColor("#C62828");
                break;
            default:
                text = "PASS - no susfs LKM detected";
                color = Color.parseColor("#2E7D32");
                break;
        }
        Log.i("LKMDET", "verdict class " + cls + ": " + text);
        ui.post(() -> {
            banner.setText(text);
            banner.setBackgroundColor(color);
            banner.setAlpha(0f);
            banner.setVisibility(View.VISIBLE);
            banner.animate().alpha(1f).setDuration(250).start();
        });
    }

    private void step(String title, Probe p) {
        post("\n" + title + "\n");
        String r;
        try {
            r = p.run();
        } catch (Throwable t) {
            r = "  !! native call failed: " + t + "\n";
        }
        Log.i("LKMDET", title + "\n" + r);
        post(r);
    }

    private void saveLog() {
        try {
            File dir = getExternalFilesDir(null);
            if (dir == null) dir = getFilesDir();
            File f = new File(dir, "lkmdet_result.txt");
            FileWriter w = new FileWriter(f, false);
            w.write(fullLog.toString());
            w.close();
            Log.i("LKMDET", "saved " + f);
            ui.post(() -> Toast.makeText(this, "Result log saved", Toast.LENGTH_SHORT).show());
        } catch (Exception e) {
            Log.w("LKMDET", "save failed", e);
        }
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
