# App-direct execution channel (no ADB / Stellar / Shizuku)

The app can jailbreak supported kernels entirely from its own sandbox:
no Stellar, no Shizuku, no ADB, no PC. This document describes the channel
as shipped in this repository.

## Which engine runs app-direct, and why

Two exploit engines live in the APK:

- The CVE-2026-98260 runners (`libk*.so`, one per kernel) are
  **tracefs-architected**: the race is observed through
  `/sys/kernel/tracing/per_cpu/cpu*/trace_pipe_raw` kmem events, the KASLR
  slide is derived from the trace-observed timer call site, and the post-race
  read primitive registers kprobes. untrusted_app has no tracefs (this
  port's own probe v1.2 found every tracefs entry invisible from the app
  domain), so the 98260 chain **cannot** run app-direct. It keeps the
  Stellar/Shizuku shell-uid path.
- The vendored **CVE-2026-43499 core** (`libghostlock.so`, Apache-2.0, from
  YuKongA/ghostlock-app under `third_party/ghostlock-core/`) is a futex PI
  UAF whose observation channel is pure syscalls. ghostlock-app proved the
  full in-app model in production: ProcessBuilder spawn from
  `nativeLibraryDir`, kernel-side seccomp strip (W3), cred install (W2),
  SELinux permissive (W1), and a root child that runs the manager
  `ksud late-load`.

App-direct = the second engine, executed inside the app sandbox
(ghostlock-app model). On kernels with a bundled GLK1 profile the app offers
an "Execution mode" selector: `Stellar / Shizuku (98260)` or
`App-direct, no PC (43499)`. When no Stellar/Shizuku backend is running the
app-direct mode is selected automatically - the one-tap button then works
with zero external setup.

## Components

| Piece | Location | Role |
| --- | --- | --- |
| Engine core | `third_party/ghostlock-core/core/` | vendored C++ (upstream tests excluded), provenance in `third_party/cve-2026-43499-LICENSES/` |
| Build script | `exploit/build-ghostlock.sh` | NDK clang++ (API 35, C++23, PIE), installs `jniLibs/arm64-v8a/libghostlock.so` (same packaging trick as the libk runners); run by CI before the APK build |
| Kernel profiles | `app/src/main/assets/ghostlock_profiles/<release>.glk1` | GLK1 binary wire documents exported with the **upstream profile-core exporter** (same ProfileMerger/ProfileResolver code as the ghostlock app), so exporter and engine cannot drift |
| LOCAL backend | `Privileged.kt` (`PrivBackend.LOCAL`) | plain ProcessBuilder spawn; `pickOrLocal()` keeps Stellar > Shizuku > LOCAL priority |
| App flow | `MainActivity.runGhostlockDirect()` | profile staging, manager ksud resolution, env contract, log streaming, device verify |

## Runtime contract

```
argv:  <nativeLibraryDir>/libghostlock.so --load-prebuilt-profile <staged .glk1>
env:   GHOSTLOCK_HOME = TMPDIR = HOME = <filesDir>/ghostlock/run  (writable work dir)
       GHOSTLOCK_KSU_LOG = <workdir>/ksu.log        (module-watch log)
       GHOSTLOCK_KSUD = <manager APK>/lib/arm64/libksud.so
       PATH = /system/bin:/system/xbin:/data/adb/ksu/bin
```

- The manager's `libksud.so` is resolved through PackageManager from the app
  domain (the shell `pm path` one-liner is a backend-only tool). All
  supported manager packages are already declared in the manifest `<queries>`
  block. If the selected manager is not installed the run fails fast with a
  clear log line - the engine never late-loads a foreign ksud silently
  (its root script falls back to a /data/app scan only when
  `GHOSTLOCK_KSUD` is unset, which this app always sets).
- The engine's root child performs `ksud late-load --kmi <kmi>` itself and
  re-enforces SELinux after module init; the app only verifies the result
  (`/proc/modules` shows `kernelsu ... Live`, `/sys/fs/selinux/enforce`
  readable directly from the app domain) and launches the manager.
- Exit codes: `0` = completed (or diagnostic early-stop with the objective
  met), `1` = failed/rejected. The app additionally requires the module to
  be live before reporting success.

## Adding a kernel to app-direct

1. A GLK1 profile for the exact `uname -r` must exist upstream (or be
   measured): export it with the upstream `:profile-core:exportKernelProfiles`
   task, verify it decodes (`read_glk1_file`) and that its offsets match the
   device, then commit it as
   `app/src/main/assets/ghostlock_profiles/<release>.glk1`.
2. Register the release in `MainActivity.GHOSTLOCK_PROFILES`.
3. The 98260 runner for that kernel is unaffected: app-direct is an
   additional option, never a replacement.

## Risk notes

- CVE-2026-43499 is a race-condition UAF like 98260; any single run can
  fail or panic the kernel. No stronger guarantee is made than the remote
  path; one attempt per clean boot remains the rule after a panic.
- The X6873 profile is the GhostLock-measured one (`recommend_shizuku = 0`),
  runtime-confirmed on device upstream (SELinux write resolved, cred
  install returned uid 0); its constants cross-check this repository's own
  98260 port (task.cred 0x838, seccomp 0x900, selinux 0x225b820).
