# Wild Detector

Environment / integrity checks for Android, run from a normal, unprivileged
app process. Zero root needed.

This app is [reveny's Native Detector](https://github.com/reveny/Android-Native-Root-Detector)
(MIT) used as the base. The home UI (check card, detection cards, info cards)
is upstream code; everything else was adjusted:

- the detection placeholder (`MainViewModel.getDetections`, which upstream
  returns `emptyList()`) is filled with the detection engine
- the native library is **libwild** (`System.loadLibrary("wild")`), built from
  `app/src/main/cpp/`: the engine + a JNI bridge for `Native.getDetections`
- the app label is Wild Detector
- **no telemetry**: the telemetry toggle was removed (nothing was ever sent
  anywhere)
- **no reveny.me connection**: update checks use this repo's GitHub releases
- **colors follow the system**: Material You dynamic color on Android 12+,
  light/dark follows the system setting; the upstream seed-color picker was
  removed
- **language + experimental-detections switches** live in the home top bar;
  the bottom bar and the settings screens were removed entirely

Only real detections are reported: a clean device gets an empty list and the
app shows "The Environment is normal". Every card shows what was detected,
what the detection means, and the evidence that tripped it; cards are grouped
by check category. The experimental-detections switch enables slower/noisier
probes on top of the always-on set.

## Build

```
./gradlew assembleRelease
```

Release builds are signed with `wilddet.keystore` (committed; store password
`android`, alias `wilddet` — same pattern as upstream demo keystores).

## Credits

- App: [reveny/Android-Native-Root-Detector](https://github.com/reveny/Android-Native-Root-Detector)
  (MIT) - used unchanged as the base
- Detection surface modeled on the reverse-engineered checks shipped in a
  mainstream production app
