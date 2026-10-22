/*
 * wilddet — environment detection engine (unprivileged, no root required)
 *
 * Detection surface ported from Uber Driver 4.602.10001 (com.ubercab.driver),
 * reverse-engineered from the shipped APK:
 *   - DEX/RootBeer layer: literal constants verified in the DEX string pool
 *     (su paths, CHECK_FOR_BINARY_{SU,MAGISK,BUSYBOX}, manager packages,
 *     emulator fingerprints, test-keys/dev-keys, userdebug)
 *   - libse.so native layer: mechanisms from the import table (setmntent,
 *     dl_iterate_phdr, /proc reads, anti-debug, getppid); Uber's indicator
 *     strings are runtime-encrypted, so each mechanism is ported with the
 *     standard indicator set for that mechanism.
 *
 * Every check reports exactly one card — hit or pass — so the UI shows what
 * is passing as well as what fired. Pass cards carry the evidence that the
 * check actually ran (probed path counts, observed property values,
 * TracerPid, scan coverage).
 *
 * Excluded on purpose (not in the Uber app, or not portable):
 *   Play Integrity / SafetyNet (server verdicts), hasMockCertVerifier
 *   (inspects Uber's own runtime), SELinux probes, bootloader property
 *   probes, custom-kernel strings.
 */

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <unistd.h>

#define WD_MAX_RESULTS 64
#define WD_DESC_MAX    2048
#define WD_NAME_MAX    160
#define WD_GROUP_MAX   64

#define WD_EXPERIMENTAL 1

/* public API (used by the JNI bridge and defined below) */
int         wilddet_run(int flags);
int         wilddet_count(void);
const char *wilddet_name(int i);
const char *wilddet_group(int i);
const char *wilddet_desc(int i);
const char *wilddet_evidence(int i);
int         wilddet_detected(int i);
void        wilddet_free(void);

typedef struct {
    char name[WD_NAME_MAX];
    char group[WD_GROUP_MAX];
    char desc[WD_DESC_MAX];
    char *evidence; /* malloc'd, may be NULL */
    int detected;   /* 1 = hit, 0 = pass / clean */
} wd_result;

static wd_result g_results[WD_MAX_RESULTS];
static int g_count = 0;

static void wd_add(const char *name, const char *group, const char *desc,
                   const char *evidence, int detected)
{
    if (g_count >= WD_MAX_RESULTS)
        return;
    wd_result *r = &g_results[g_count];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->group, sizeof(r->group), "%s", group);
    snprintf(r->desc, sizeof(r->desc), "%s", desc);
    r->evidence = (evidence && evidence[0]) ? strdup(evidence) : NULL;
    r->detected = detected ? 1 : 0;
    g_count++;
}

static int wd_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int wd_getprop(const char *name, char *out, size_t outlen)
{
    char value[PROP_VALUE_MAX];
    int len = __system_property_get(name, value);
    if (len <= 0)
        return 0;
    value[len] = 0;
    snprintf(out, outlen, "%s", value);
    return 1;
}

static void wd_strlower(char *s)
{
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

/* --------------------------------------------------------------------- */
/* DEX/RootBeer layer: su binaries                                        */
/* --------------------------------------------------------------------- */

static const char *SU_PATHS[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/",                 /* RootBeer constant, trailing slash */
    "/system/bin/failsafe/su",
    "/system/bin/.ext/.su/",    /* SuperSU installer path */
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/sd/xbin/su",
    "/system/xbin/daemonsu",    /* SuperSU daemon */
    "/system/etc/.has_su_daemon",
};

static const char *DESC_SU_PATHS =
    "Probes the standard root paths for a su binary or SuperSU daemon. "
    "Uber's RootBeer layer checks exactly these paths as compiled constants "
    "(CHECK_FOR_BINARY_SU; strings verified in com.ubercab.driver "
    "4.602.10001). KernelSU/Magisk setups that keep su off these paths do "
    "not trip this.";

static void check_su_paths(void)
{
    char ev[4096];
    size_t used = 0;
    int hits = 0;
    ev[0] = 0;

    for (size_t i = 0; i < sizeof(SU_PATHS) / sizeof(SU_PATHS[0]); i++) {
        const char *p = SU_PATHS[i];
        char probe[300];
        snprintf(probe, sizeof(probe), "%s", p);
        size_t l = strlen(probe);
        if (l && probe[l - 1] == '/') {
            /* trailing-slash constants: probe the binary name too */
            char with[304];
            snprintf(with, sizeof(with), "%ssu", probe);
            if (!wd_file_exists(with) && !wd_file_exists(probe))
                continue;
            snprintf(probe, sizeof(probe), "%s", with);
        } else if (!wd_file_exists(probe)) {
            continue;
        }
        int n = snprintf(ev + used, sizeof(ev) - used, "%s%s",
                         hits ? "\n" : "", probe);
        if (n > 0 && (size_t)n < sizeof(ev) - used)
            used += (size_t)n;
        hits++;
    }

    if (hits) {
        wd_add("su binary scan", "Root binaries", DESC_SU_PATHS, ev, 1);
    } else {
        snprintf(ev, sizeof(ev),
                 "probed %zu standard root paths — none present",
                 sizeof(SU_PATHS) / sizeof(SU_PATHS[0]));
        wd_add("su binary scan", "Root binaries", DESC_SU_PATHS, ev, 0);
    }
}

static void check_superuser_apk(void)
{
    wd_add("Superuser.apk scan",
           "Root binaries",
           "/system/app/Superuser.apk (RootBeer constant superUserApk, "
           "compiled into the Uber app) is a legacy Superuser install on the "
           "system partition — usually a manually patched system image.",
           wd_file_exists("/system/app/Superuser.apk")
               ? "/system/app/Superuser.apk present"
               : "probed /system/app/Superuser.apk — not present",
           wd_file_exists("/system/app/Superuser.apk"));
}

/* --------------------------------------------------------------------- */
/* DEX/RootBeer layer: CHECK_FOR_BINARY exec probes                       */
/* --------------------------------------------------------------------- */

static void check_exec_probes(void)
{
    /* RootBeer's CHECK_FOR_BINARY_{SU,MAGISK,BUSYBOX}: resolve the binaries
     * through PATH with which(1), as RootBeer's helper does. */
    FILE *fp = popen("/system/bin/sh -c 'which su; which magisk; which busybox' 2>/dev/null",
                     "r");
    if (!fp) {
        wd_add("root binary in PATH",
               "Root binaries",
               "Uber's CHECK_FOR_BINARY_{SU,MAGISK,BUSYBOX} probe (feature "
               "flags compiled into the DEX): which(1) resolves su, magisk "
               "or busybox on the app's PATH.",
               "could not spawn which(1) — check skipped", 0);
        return;
    }
    char line[512], ev[1024];
    ev[0] = 0;
    int hits = 0;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0])
            continue;
        if (hits)
            strncat(ev, "\n", sizeof(ev) - strlen(ev) - 2);
        strncat(ev, line, sizeof(ev) - strlen(ev) - 2);
        hits++;
    }
    pclose(fp);

    if (hits) {
        wd_add("root binary in PATH",
               "Root binaries",
               "Uber's CHECK_FOR_BINARY_{SU,MAGISK,BUSYBOX} probe (feature "
               "flags compiled into the DEX): which(1) resolved one of the "
               "root binaries on the app's PATH — the binary is executable "
               "from an unprivileged app context.",
               ev, 1);
    } else {
        wd_add("root binary in PATH",
               "Root binaries",
               "Uber's CHECK_FOR_BINARY_{SU,MAGISK,BUSYBOX} probe (feature "
               "flags compiled into the DEX): which(1) resolves su, magisk "
               "or busybox on the app's PATH.",
               "which su/magisk/busybox — no results on PATH", 0);
    }
}

/* --------------------------------------------------------------------- */
/* DEX/RootBeer layer: build integrity (test-keys/dev-keys, userdebug)    */
/* --------------------------------------------------------------------- */

static void check_build_tags(void)
{
    char tags[PROP_VALUE_MAX] = "";
    wd_getprop("ro.build.tags", tags, sizeof(tags));

    int hit = strstr(tags, "test-keys") != NULL ||
              strstr(tags, "dev-keys") != NULL;
    char ev[PROP_VALUE_MAX + 64];
    snprintf(ev, sizeof(ev), "ro.build.tags = %s", tags[0] ? tags : "(unset)");
    wd_add("build signing keys",
           "Build integrity",
           "ro.build.tags is compared against test-keys/dev-keys. Uber's "
           "RootBeer layer ships both constants (DEX string pool) to flag "
           "non-release-key builds — i.e. a custom or self-signed system "
           "image.",
           ev, hit);
}

static void check_build_type(void)
{
    char type[PROP_VALUE_MAX] = "";
    wd_getprop("ro.build.type", type, sizeof(type));

    int hit = (strcmp(type, "userdebug") == 0 || strcmp(type, "eng") == 0);
    char ev[PROP_VALUE_MAX + 64];
    snprintf(ev, sizeof(ev), "ro.build.type = %s", type[0] ? type : "(unset)");
    wd_add("build type",
           "Build integrity",
           "ro.build.type is compared against userdebug/eng. The userdebug "
           "constant is compiled into Uber's RootBeer-derived check table "
           "(adjacent to the emulator constants in the DEX string pool). "
           "Rooted custom ROMs frequently run userdebug builds.",
           ev, hit);
}

/* --------------------------------------------------------------------- */
/* DEX/RootBeer layer: emulator fingerprints                              */
/* --------------------------------------------------------------------- */

static void check_emulator_props(void)
{
    char ev[1024];
    ev[0] = 0;
    int hits = 0;

    char hw[PROP_VALUE_MAX] = "";
    wd_getprop("ro.hardware", hw, sizeof(hw));
    char dev[PROP_VALUE_MAX] = "";
    wd_getprop("ro.product.device", dev, sizeof(dev));

    char lower[PROP_VALUE_MAX];
    snprintf(lower, sizeof(lower), "%s", hw);
    wd_strlower(lower);
    if (strstr(lower, "goldfish") || strstr(lower, "ranchu") ||
        strstr(lower, "vbox86")) {
        size_t at = strlen(ev);
        snprintf(ev + at, sizeof(ev) - at, "ro.hardware = %s\n", hw);
        hits++;
    }

    snprintf(lower, sizeof(lower), "%s", dev);
    wd_strlower(lower);
    if (strstr(lower, "vbox86") || strstr(lower, "generic_x86")) {
        size_t at = strlen(ev);
        snprintf(ev + at, sizeof(ev) - at, "ro.product.device = %s\n", dev);
        hits++;
    }

    char observed[2 * PROP_VALUE_MAX + 64];
    snprintf(observed, sizeof(observed),
             "ro.hardware = %s\nro.product.device = %s",
             hw[0] ? hw : "(unset)", dev[0] ? dev : "(unset)");

    if (hits) {
        size_t at = strlen(ev);
        while (at && (ev[at - 1] == '\n'))
            ev[--at] = 0;
        wd_add("emulator property fingerprints",
               "Emulator",
               "System properties match the emulator fingerprints compiled "
               "into Uber's RootBeer layer: GOLDFISH / RANCHU (AOSP emulator "
               "hardware), vbox86 (VirtualBox/Genymotion), GENERIC_X86 "
               "(generic x86 builds).",
               ev, 1);
    } else {
        wd_add("emulator property fingerprints",
               "Emulator",
               "System properties are compared against the emulator "
               "fingerprints compiled into Uber's RootBeer layer: GOLDFISH / "
               "RANCHU (AOSP emulator hardware), vbox86 "
               "(VirtualBox/Genymotion), GENERIC_X86 (generic x86 builds).",
               observed, 0);
    }
}

static void check_emulator_files(void)
{
    static const struct {
        const char *path;
        const char *what;
    } EMU_FILES[] = {
        { "/dev/qemu_pipe", "QEMU fast pipe (goldfish/ranchu)" },
        { "/dev/socket/qemud", "QEMU daemon socket" },
        { "/system/lib/libc_malloc_debug_qemu.so", "emulator-only malloc debug lib" },
        { "/system/bin/qemu-props", "QEMU property injector" },
        { "/system/bin/noxd", "Nox emulator daemon" },
        { "/system/bin/genymotion-vbox-sf", "Genymotion VBox shared-folder helper" },
        { "/system/bin/genybaseband", "Genymotion baseband helper" },
        { "/init.vbox86.rc", "VirtualBox init script" },
        { "/init.ttVM_x86.rc", "Tencent VM init script" },
        { "/fstab.vbox86", "VirtualBox fstab" },
        { "/fstab.ttVM_x86", "Tencent VM fstab" },
        { "/ueventd.android_x86.rc", "Android-x86 ueventd" },
        { "/ueventd.android_x86_64.rc", "Android-x86_64 ueventd" },
        { "/ueventd.andy.rc", "Andy emulator ueventd" },
        { "/ueventd.nox.rc", "Nox emulator ueventd" },
        { "/ueventd.ttVM_x86.rc", "Tencent VM ueventd" },
    };

    char ev[2048];
    ev[0] = 0;
    int hits = 0;
    for (size_t i = 0; i < sizeof(EMU_FILES) / sizeof(EMU_FILES[0]); i++) {
        if (!wd_file_exists(EMU_FILES[i].path))
            continue;
        size_t at = strlen(ev);
        int n = snprintf(ev + at, sizeof(ev) - at, "%s%s — %s\n",
                         hits ? "" : "", EMU_FILES[i].path, EMU_FILES[i].what);
        if (n <= 0)
            break;
        hits++;
    }

    if (hits) {
        size_t at = strlen(ev);
        while (at && (ev[at - 1] == '\n'))
            ev[--at] = 0;
        wd_add("emulator filesystem artifacts",
               "Emulator",
               "Device nodes, daemons or init scripts exist that only "
               "emulators create. Uber's RootBeer layer compiles this exact "
               "set (verified strings: /dev/qemu_pipe, /dev/socket/qemud, "
               "libc_malloc_debug_qemu.so, bin/genymotion-vbox-sf, "
               "bin/genybaseband, fstab.vbox86, init.vbox86.rc, "
               "ueventd.{android_x86,android_x86_64,andy,nox,ttVM_x86}.rc).",
               ev, 1);
    } else {
        snprintf(ev, sizeof(ev),
                 "probed %zu emulator-only artifacts — none present",
                 sizeof(EMU_FILES) / sizeof(EMU_FILES[0]));
        wd_add("emulator filesystem artifacts",
               "Emulator",
               "Device nodes, daemons or init scripts are probed that only "
               "emulators create. Uber's RootBeer layer compiles this exact "
               "set (verified strings: /dev/qemu_pipe, /dev/socket/qemud, "
               "libc_malloc_debug_qemu.so, bin/genymotion-vbox-sf, "
               "bin/genybaseband, fstab.vbox86, init.vbox86.rc, "
               "ueventd.{android_x86,android_x86_64,andy,nox,ttVM_x86}.rc).",
               ev, 0);
    }
}

/* --------------------------------------------------------------------- */
/* libse.so layer: mount-table scan (setmntent/getmntent)                 */
/* --------------------------------------------------------------------- */

static int wd_mountpoint_notable(const char *mp)
{
    static const char *SYSTEM_DIRS[] = { "/system", "/vendor", "/product",
                                         "/system_ext", "/odm" };
    for (size_t i = 0; i < sizeof(SYSTEM_DIRS) / sizeof(SYSTEM_DIRS[0]); i++)
        if (strcmp(mp, SYSTEM_DIRS[i]) == 0)
            return 1;
    return 0;
}

static void check_mounts(void)
{
    static const char *MOUNT_FILES[] = { "/proc/self/mounts",
                                         "/proc/self/mountinfo" };
    char ev[4096];
    ev[0] = 0;
    int hits = 0;
    long scanned = 0;

    for (size_t f = 0; f < sizeof(MOUNT_FILES) / sizeof(MOUNT_FILES[0]); f++) {
        FILE *fp = fopen(MOUNT_FILES[f], "r");
        if (!fp)
            continue;
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = 0;
            scanned++;

            int notable = 0;

            if (strstr(line, "magisk")) {
                notable = 1;
            } else if (strstr(line, " overlay ")) {
                /* module mounts: overlay over a system partition, or an
                 * upperdir backed by /data/adb (Magisk modules and
                 * KernelSU mounts both live there) */
                char mp[512];
                mp[0] = 0;
                if (f == 0) { /* /proc/self/mounts: mountpoint = field 2 */
                    char dev[256], m[512], fs[128];
                    if (sscanf(line, "%255s %511s %127s", dev, m, fs) >= 2)
                        snprintf(mp, sizeof(mp), "%s", m);
                } else { /* mountinfo: mountpoint = field 5 */
                    char f1[64], f2[64], f3[64], f4[64], m[512];
                    if (sscanf(line, "%63s %63s %63s %63s %511s",
                               f1, f2, f3, f4, m) >= 5)
                        snprintf(mp, sizeof(mp), "%s", m);
                }
                if (wd_mountpoint_notable(mp) ||
                    strstr(line, "upperdir=/data/adb"))
                    notable = 1;
            }

            if (notable) {
                size_t at = strlen(ev);
                snprintf(ev + at, sizeof(ev) - at, "%s%s\n",
                         hits ? "" : "", line);
                hits++;
                if (strlen(ev) > sizeof(ev) - 256)
                    break;
            }
        }
        fclose(fp);
    }

    if (hits) {
        size_t at = strlen(ev);
        while (at && (ev[at - 1] == '\n'))
            ev[--at] = 0;
        wd_add("root module mounts",
               "Mount table",
               "The mount table exposes Magisk/module mounts: entries "
               "referencing magisk, or overlay filesystems mounted over "
               "system partitions / backed by upperdirs under /data/adb "
               "(where Magisk modules and KernelSU mounts live). This ports "
               "libse.so's setmntent/getmntent mount scan — Uber's native "
               "engine reads /proc/mounts at runtime; its comparison strings "
               "are encrypted, so the standard root-mount indicators are "
               "used here.",
               ev, 1);
    } else {
        snprintf(ev, sizeof(ev),
                 "scanned /proc/self/mounts + /proc/self/mountinfo "
                 "(%ld entries) — no magisk entries, no overlays over system "
                 "partitions, no upperdirs under /data/adb",
                 scanned);
        wd_add("root module mounts",
               "Mount table",
               "The mount table is scanned for Magisk/module mounts: entries "
               "referencing magisk, or overlay filesystems mounted over "
               "system partitions / backed by upperdirs under /data/adb "
               "(where Magisk modules and KernelSU mounts live). This ports "
               "libse.so's setmntent/getmntent mount scan — Uber's native "
               "engine reads /proc/mounts at runtime; its comparison strings "
               "are encrypted, so the standard root-mount indicators are "
               "used here.",
               ev, 0);
    }
}

/* --------------------------------------------------------------------- */
/* libse.so layer: loaded-module enumeration (dl_iterate_phdr + maps)     */
/* --------------------------------------------------------------------- */

static const char *HOOK_PATTERNS[] = {
    "frida", "xposed", "edxposed", "lsposed", "substrate",
    "riru", "zygisk", "lsplant", "sandhook",
};

static int g_phdr_total = 0;

static int wd_name_matches_hook(const char *s, char *which, size_t whichlen)
{
    if (!s || !s[0])
        return 0;
    char lower[1024];
    snprintf(lower, sizeof(lower), "%s", s);
    wd_strlower(lower);
    for (size_t i = 0; i < sizeof(HOOK_PATTERNS) / sizeof(HOOK_PATTERNS[0]);
         i++) {
        if (strstr(lower, HOOK_PATTERNS[i])) {
            snprintf(which, whichlen, "%s", HOOK_PATTERNS[i]);
            return 1;
        }
    }
    return 0;
}

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    g_phdr_total++;
    char which[64];
    if (wd_name_matches_hook(info->dlpi_name, which, sizeof(which))) {
        char *ev = (char *)data;
        size_t at = strlen(ev);
        snprintf(ev + at, 4096 - at, "%s(dl_phdr) %s\n",
                 ev[0] ? "\n" : "", info->dlpi_name);
    }
    return 0;
}

static void check_injected_libs(void)
{
    char ev[4096];
    ev[0] = 0;
    int hits = 0;
    long maps_lines = 0;

    /* 1) /proc/self/maps — covers libs mapped outside the linker list */
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            maps_lines++;
            char which[64];
            /* basename-ish: last path component in the mapping line */
            char *slash = strrchr(line, '/');
            if (!slash)
                continue;
            char name[256];
            snprintf(name, sizeof(name), "%s", slash + 1);
            name[strcspn(name, " \n")] = 0;
            if (!wd_name_matches_hook(name, which, sizeof(which)))
                continue;
            size_t at = strlen(ev);
            snprintf(ev + at, sizeof(ev) - at, "%s(maps) %s\n",
                     hits ? "\n" : "", name);
            hits++;
            if (strlen(ev) > sizeof(ev) - 256)
                break;
        }
        fclose(fp);
    }

    /* 2) dl_iterate_phdr — libse.so's own loaded-module walk */
    g_phdr_total = 0;
    char phdr_ev[4096];
    phdr_ev[0] = 0;
    dl_iterate_phdr(phdr_callback, phdr_ev);
    if (phdr_ev[0]) {
        size_t at = strlen(ev);
        snprintf(ev + at, sizeof(ev) - at, "%s%s", hits ? "\n" : "", phdr_ev);
        hits++;
    }

    if (hits) {
        size_t at = strlen(ev);
        while (at && (ev[at - 1] == '\n'))
            ev[--at] = 0;
        wd_add("hooking framework injection",
               "Hooking / injection",
               "A known hooking/injection framework library is loaded into "
               "this process (Frida, Xposed/EdXposed/LSPosed, Substrate, "
               "Riru, Zygisk, LSPlant, SandHook). Uber's DEX contains no "
               "hook indicators at all — libse.so does this scan natively "
               "via dl_iterate_phdr + dlopen and /proc reads, with "
               "runtime-encrypted indicator strings; the standard framework "
               "names are used here.",
               ev, 1);
    } else {
        snprintf(ev, sizeof(ev),
                 "scanned /proc/self/maps (%ld mappings) and %d linker "
                 "modules via dl_iterate_phdr — no frida / xposed / "
                 "substrate / riru / zygisk / lsplant / sandhook matches",
                 maps_lines, g_phdr_total);
        wd_add("hooking framework injection",
               "Hooking / injection",
               "The process's loaded libraries are scanned for known "
               "hooking/injection frameworks (Frida, Xposed/EdXposed/LSPosed, "
               "Substrate, Riru, Zygisk, LSPlant, SandHook). Uber's DEX "
               "contains no hook indicators at all — libse.so does this scan "
               "natively via dl_iterate_phdr + dlopen and /proc reads, with "
               "runtime-encrypted indicator strings; the standard framework "
               "names are used here.",
               ev, 0);
    }
}

/* --------------------------------------------------------------------- */
/* libse.so layer: anti-debug (TracerPid)                                 */
/* --------------------------------------------------------------------- */

static void check_tracerpid(void)
{
    FILE *fp = fopen("/proc/self/status", "r");
    int tracer = 0;
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer = atoi(line + 10);
                break;
            }
        }
        fclose(fp);
    }

    char ev[64];
    snprintf(ev, sizeof(ev), "TracerPid = %d", tracer);
    wd_add("debugger attached",
           "Process context",
           "TracerPid in /proc/self/status is checked: nonzero means a "
           "debugger or ptrace-based injector is attached to this process. "
           "libse.so guards itself against exactly this (ptrace-capable "
           "syscalls, mprotect/mlock self-checks, controlled aborts).",
           ev, tracer > 0);
}

/* --------------------------------------------------------------------- */
/* libse.so layer: parent process check (getppid)                         */
/* --------------------------------------------------------------------- */

static void check_ppid(void)
{
    static const char *DESC_PARENT =
        "The parent of an app process is checked against zygote (titled "
        "zygote64/zygote, binary app_process). A readable parent cmdline "
        "that is neither means this process was spawned outside the normal "
        "app lifecycle (e.g. injected runner). libse.so imports getppid for "
        "exactly this class of process-context check. Because /proc is "
        "mounted hidepid=2, the parent cmdline is usually unreadable from "
        "an app — in that case the check is inconclusive and reported as "
        "clean.";

    FILE *fp = fopen("/proc/self/stat", "r");
    if (!fp) {
        wd_add("parent process",
               "Process context",
               DESC_PARENT,
               "could not read /proc/self/stat — check skipped", 0);
        return;
    }
    char stat[1024];
    size_t n = fread(stat, 1, sizeof(stat) - 1, fp);
    fclose(fp);
    stat[n] = 0;

    /* pid (comm) state ppid ... — field 4 is ppid, after the ')' */
    char *close_paren = strrchr(stat, ')');
    int ppid = 0;
    if (close_paren) {
        char state;
        if (sscanf(close_paren + 1, " %c %d", &state, &ppid) != 2)
            ppid = 0;
    }
    if (ppid <= 0) {
        wd_add("parent process",
               "Process context",
               DESC_PARENT,
               "could not parse ppid from /proc/self/stat — check skipped", 0);
        return;
    }

    char cmdpath[64];
    snprintf(cmdpath, sizeof(cmdpath), "/proc/%d/cmdline", ppid);
    char parent[256];
    parent[0] = 0;
    fp = fopen(cmdpath, "r");
    if (fp) {
        size_t got = fread(parent, 1, sizeof(parent) - 1, fp);
        fclose(fp);
        parent[got] = 0;
    }

    if (parent[0] == 0) {
        /* /proc is mounted hidepid=2: another uid's cmdline (zygote's) is
         * not readable from an app. Inconclusive — not a detection. */
        char ev[128];
        snprintf(ev, sizeof(ev),
                 "ppid = %d; parent cmdline not readable (hidepid) — "
                 "inconclusive, treated clean", ppid);
        wd_add("parent process", "Process context", DESC_PARENT, ev, 0);
        return;
    }

    int hit = !strstr(parent, "zygote") && !strstr(parent, "app_process");
    char ev[512];
    snprintf(ev, sizeof(ev), "ppid = %d, parent cmdline = %s", ppid, parent);
    wd_add("parent process", "Process context", DESC_PARENT, ev, hit);
}

/* --------------------------------------------------------------------- */
/* Public API                                                             */
/* --------------------------------------------------------------------- */

int wilddet_run(int flags)
{
    wilddet_free();
    check_su_paths();
    check_superuser_apk();
    if (flags & WD_EXPERIMENTAL)
        check_exec_probes();
    check_build_tags();
    check_build_type();
    check_emulator_props();
    check_emulator_files();
    check_mounts();
    check_injected_libs();
    check_tracerpid();
    check_ppid();
    return g_count;
}

int wilddet_count(void)
{
    return g_count;
}

const char *wilddet_name(int i)   { return (i >= 0 && i < g_count) ? g_results[i].name     : ""; }
const char *wilddet_group(int i)  { return (i >= 0 && i < g_count) ? g_results[i].group    : ""; }
const char *wilddet_desc(int i)   { return (i >= 0 && i < g_count) ? g_results[i].desc     : ""; }
const char *wilddet_evidence(int i)
{
    return (i >= 0 && i < g_count && g_results[i].evidence) ? g_results[i].evidence : "";
}
int wilddet_detected(int i)       { return (i >= 0 && i < g_count) ? g_results[i].detected : 0; }

void wilddet_free(void)
{
    for (int i = 0; i < g_count; i++) {
        free(g_results[i].evidence);
        g_results[i].evidence = NULL;
    }
    g_count = 0;
}
