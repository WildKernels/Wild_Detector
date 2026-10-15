# Wild Detector

Detects the **susfs4ksu-lkm** loadable-module port (inforcqb's LKM build of
susfs4ksu) from a normal, unprivileged app process. Zero root needed.

This app is [reveny's Native Detector](https://github.com/reveny/Android-Native-Root-Detector)
(MIT) used as the base, **as-is**: the entire UI, settings, update checker and
layout are upstream code. The only changes:

- the detection placeholder (`MainViewModel.getDetections`, which upstream
  returns `emptyList()`) is filled with the real engine
- the native library is **libwild** (`System.loadLibrary("wild")`), built from
  `app/src/main/cpp/`: the lkmdet engine + a JNI bridge for
  `Native.getDetections`
- the app label is Wild Detector

## What it detects

Only real detections are reported (clean device -> empty list -> the app shows
"The Environment is normal"):

- **getdents64 race leak** - the LKM hides its `/proc/susfs_*` entries from
  directory listings, but the hidden names leak out of the kernel buffer
  during an mprotect/uaccess race
- **/proc O_PATH inconsistency** - the LKM's hiding layer fails open:
  `/proc/susfs_*` passes `open(O_PATH)` but `fstat` reports `ENOENT`,
  impossible on a clean kernel

Built-in susfs (e.g. WildKernels) does not trip either probe.

## Credits

- App: [reveny/Android-Native-Root-Detector](https://github.com/reveny/Android-Native-Root-Detector)
  (MIT) - used unchanged as the base
- Engine: lkmdet, from the WildKernels susfs LKM audit
