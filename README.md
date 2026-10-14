# Wild Detector (lkmdet) — non-root susfs LKM detector (arm64)

Detects the **LKM port of susfs** (`inforcqb/susfs4ksu-lkm`, module
`susfs_guard_lkm`) **without root**, and distinguishes it from a clean
kernel and from built-in susfs. Two frontends, one engine:

- `lkmdet` — standalone adb-shell binary (uid 2000 = the exact non-root
  surface the LKM's self-hide rules are written against)
- `LKMDet.apk` — zero-permission installable app (same probes via JNI)

Everything is unprivileged syscalls + world-readable files. Running as
root is pointless — the LKM's self-hide rules only apply to non-root
callers.

## Probes

- **P1 zero-ino placeholder records** (deterministic): the LKM rewrites
  getdents64 buffers *after* the syscall. When a whole chunk is hidden it
  emits a `d_ino=0`/empty-name placeholder record (sus_path.c:1612-1648)
  because returning 0 would read as early-EOF. Clean kernels never emit
  one (procfs/sysfs inos are never 0); built-in susfs never emits one (its
  filldir64 hook drops the entry before it reaches the buffer). Forced
  deterministically with 56-byte (single-record) chunks over `/proc` and
  `/sys/module`.
- **P2 mprotect/uaccess race** (probabilistic, definitive on hit): the
  post-hoc compaction runs under `pagefault_disable()`; a second thread
  flipping the listing buffer to `PROT_NONE` mid-syscall makes it fault →
  the filter bails and returns the *unfiltered* buffer
  (sus_path.c:1603-1609), and the tail-scrub leak is documented in their
  own comment (sus_path.c:1651+). Literal `susfs_*` names come back. The
  toggler thread parks behind a seq-cst settled handshake so it can never
  leave the buffer `PROT_NONE` while the parser reads it.
- **P3 /proc/sys/kernel/tainted**: the module has zero taint-scrub code;
  an out-of-tree/unsigned `.ko` sets O (bit 10) / E (bit 11) forever.
  Built-in susfs never taints.
- **P4 /proc/modules grep**: line is normally filtered for every caller
  by an m_show kprobe; leaks if that probe ever fails to arm.
- **P5 /proc/kallsyms grep**: `[susfs_guard_lkm]`-tagged lines = LKM;
  bare `susfs_*` kernel symbols = **built-in susfs built without
  `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS`** (fix the defconfig).
- **P6 O_PATH/fstat consistency** on the LKM's own `/proc/susfs_*` nodes:
  `open(O_PATH)` ok + `fstat → ENOENT` is impossible on a clean kernel;
  fires when the module's non-fatal opath layer failed to install.
- **P7 syscall latency medians** (INFO): gettid control vs statx vs
  reboot-with-susfs-magic. Kprobe BRK hooks add ~1-2 µs per hooked call.

## Binary usage

```sh
./build.sh                                   # NDK clang, arm64
adb push lkmdet /data/local/tmp/lkmdet
adb shell chmod 755 /data/local/tmp/lkmdet
adb shell /data/local/tmp/lkmdet             # full run (~12s, 10s race)
adb shell /data/local/tmp/lkmdet -r 30       # longer race budget
adb shell /data/local/tmp/lkmdet -d /data/local/tmp   # extra scan dir
```

## APK

```sh
./build-apk.sh          # NDK lib + javac + d8 + aapt2 + zipalign + apksigner
adb install -r LKMDet.apk
adb shell am start -n com.wildkernels.lkmdetector/.MainActivity
```

- Zero Android permissions (no manifest `uses-permission` at all).
- Terminal-style UI; tap **RUN SCAN** → results stream per probe.
- Output mirrors to `adb logcat -s LKMDET` and saves to the app's files
  dir; the build is `debuggable`, so results can be pulled without root:
  `adb shell run-as com.wildkernels.lkmdetector cat /sdcard/Android/data/com.wildkernels.lkmdetector/files/lkmdet_result.txt`
- `build-apk.sh` generates a local keystore on first run
  (`lkmdet.keystore`, gitignored — never commit it).

Both scripts assume NDK at `/opt/android-ndk` and SDK at
`/opt/android-sdk` (edit the top of each script to move them).

## CI: auto tag + release

`.github/workflows/autotag.yml` — every push to `main` (or manual
`workflow_dispatch`) builds both frontends, claims the next `vN` tag, and
publishes a GitHub release with:

- `LKMDet-vN.apk` — signed with the repo secret `LKMDET_KEYSTORE`
- `lkmdet-vN` — arm64 adb-shell binary

The build runs **before** tagging, so a broken build burns no version
number. Releases are signed with the repo secret so every release
installs over the previous one. First-time setup from a fresh clone:

```sh
./build-apk.sh                    # generates lkmdet.keystore locally
base64 -w0 lkmdet.keystore | gh secret set LKMDET_KEYSTORE --repo TheWildJames/Wild_Detector
```

Without the secret the workflow still builds, but with a fresh key per
run (updates then need an uninstall first).

## Verdict semantics

- **LKM DETECTED** — placeholder, leak, impossible-state, module-tagged
  symbols, or /proc/modules line.
- **built-in, symbols exposed** — fix the defconfig.
- **taint O/E only** — unsigned module loaded, LKM prime suspect.
- **clean** — indistinguishable from properly hidden built-in susfs (by
  design; that indistinguishability *is* the argument for built-in).

## Baseline on WildKernels

Pixel 8, `6.1.157-android14-Wild` (built-in susfs): all probes negative —
0 placeholders, no leak, no taint flags, no visible symbols — i.e. the
correct "built-in/clean" verdict. Hosted clean-kernel baseline matches.

Source of every oracle: the susfs4ksu-lkm audit (2026-10), repos kept at
`~/Projects/susfs4ksu-lkm` and `~/Projects/susfs4ksu`.
