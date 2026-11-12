# Infinix GT 30 Pro (X6873) — CVE-2026-98260 port

## Status

**Scaffolding, fail-closed — constants partially derived.** The X6873
chain is wired end to end (runner feature, plant, app integration). The
2026-11-12 on-device probe bundle filled the low21 call-site constants
and all three slab size pairs (see "Probe results" below); the KASLR
slide pinned static addresses (`timer_site` and the five data symbols)
still need one `tools/derive-consts.sh` run under `su` (v2 handles this
build's `kptr_restrict=2` itself). Until they are pasted in, the plant
refuses to start and prints `PORT_61157_PENDING` instead of touching
the kernel.

Engine compatibility is **not yet proven on 6.1** — see the caveat at the
bottom. This port follows the same posix-cpu-timers engine as the 6.18 /
6.12 / 6.6 chains; whether the race behaves identically on
`6.1.157-android14` can only be answered by the on-device run. The
2026-11-12 probe also confirmed `CONFIG_KASAN_HW_TAGS=y` and
`CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` on this build — engine-level risk
factors for the spray stages, noted in the caveat.

## Target device

- Model: Infinix GT 30 Pro (`X6873`)
- SoC: MediaTek Dimensity 8350 Ultimate (MT6897)
- OS: XOS 16 (Android 16; the device launched on XOS 15 / kernel 6.1.112 —
  that build is NOT covered, only the 6.1.157 update)
- Known builds carrying this kernel: `X6873-16.2.0.135SP13`,
  `X6873-16.3.0.150SP09`
- Kernel (exact `uname -r`): `6.1.157-android14-11-ga8b0b542991e-ab15601211`
- Bootloader: locked (the whole point of the exploit chain)

## App integration

X6873 ships as an independent chain, no constants shared with the other
entries:

- `ExploitKind.CVE61157` is auto-selected only when `uname -r` equals the
  release string above (`PROFILE_BY_RELEASE`).
- The app runs `$nativeLibraryDir/libk61157.so run` — the single-entry
  Rust runner built from `exploit/rust-kplant --features k61157`
  (`build.rs` compiles `exploit/src/K61157_plant.c`).
- Extras for this chain: the anti-root popup switch and soft-reboot stay;
  SUSFS, VFS, kernel-security unload and Dynamic Switching are hidden —
  there is no 6.1 guard LKM, no 6.1 universal KSU KO and no
  vivo-style load gate involved.
- Normal mode requires a manager APK that carries an `android14-6.1`
  LKM (KernelSU family managers ship GKI `6.1-android14` modules).
  Verify the module actually loads on this Transsion build before
  relying on it — vendor kernels are not always KMI-clean.

## Exploit chain (engine steps, no vendor-gate extras)

1. Win the CVE-2026-98260 posix-cpu-timers race for a zero write and a
   fake-cred write primitive (spray posix timers, reclaim the slab page
   as a cred page).
2. Point the target task's `task_struct.cred` (offset `0x838`, measured)
   at the fake cred in the reclaimed order-1 page.
3. Zero `selinux_state.enforcing` (image offset `0x225b820`, measured —
   the plant constant stores `+7` per the engine's `-7` write).
4. Clear `panic_on_warn` (address pending derivation).
5. Fix the fake cred's `user/user_ns/ucounts/group_info` fields to point
   at `root_user` / `init_user_ns` / `init_ucounts` / `init_groups`
   (addresses pending derivation; struct offsets `0x88/0x90/0x98/0xa0`
   already match the 6.1 credential template).
6. Wake the root child, run `ksud late-load` for the selected manager.

## Constants

Sources: `GL` = GhostLock X6873 kernel profile for this exact release
(measured on device, 33/33 boots), `P` = offline analysis of the
2026-11-12 probe bundle (`x6873_probe_20261112_195833`, build
`301500018`, slot `_b`), `D` = pending on-device derivation via
`tools/derive-consts.sh`.

| Constant | Value | Source | Status |
|---|---|---|---|
| release | `6.1.157-android14-11-ga8b0b542991e-ab15601211` | GL | final |
| `OFF_TASK_CRED` | `0x838` (`task_struct.cred = 2104`) | GL | final |
| `task_struct.real_cred` | `0x830` (2096) | GL | reference |
| `SELINUX_STATE_STATIC` | `0xffffffc08225b827` (= enforcing `0x225b820` + base + 7) | GL | final (script re-verifies) |
| cred layout (`caps 0x30 ×5`, `security 0x80`, `user 0x88`, `user_ns 0x90`, `ucounts 0x98`, `group_info 0xa0`) | matches engine template | GL 6.x credential template | final |
| `TIMER_SITE_LOW21` | `0x19feb0` (139/139 timer allocs, 15 pids, one site) | P | final (prober re-verifies) |
| `COPY_PROCESS_LOW21` | `0xac148` (29/29 fork-churn allocs, fork.c cluster) | P | final (prober re-verifies) |
| `STATIC_TIMER_SITE` | — | D | pending (runtime site seen `0xffffffe0d2d9feb0`; frame pin needs the derive run) |
| `PANIC_ON_WARN_STATIC` | — | D | pending |
| `ROOT_USER_STATIC` | — | D | pending |
| `INIT_USER_NS_STATIC` | — | D | pending |
| `INIT_UCOUNTS_STATIC` | — | D | pending |
| `INIT_GROUPS_STATIC` | — | D | pending |
| `TIMER_REQ` / `TIMER_ALLOC` | `0x108` / `0x140` (139 events) | P | final |
| `CRED_REQ` / `CRED_ALLOC` | `0xb0` / `0xc0` (65 events) | P | final |
| `TASK_ALLOC_BYTES` / `TASK_ALLOC_PADDED` | `0x12c0` / `0x12c0` (29 events) | P | final |
| KASLR slide anchors (`init_task 0x201f640`, `init_cred 0x2031aa8`, `root_task_group 0x2209980`) | used by the derive script to pin the slide | GL | reference |

## Base-address convention

The static addresses in a Shark plant are linked-image VAs under the
`0xffffffc080000000` base used by the other GKI ports. The engine only
needs internal consistency: it computes the KASLR slide at runtime as
`observed_timer_site - STATIC_TIMER_SITE`, and every write goes to
`STATIC_x + slide`. A constant shift in the base cancels out, so the
derive script pins the slide against the three GhostLock-measured image
offsets (`init_task` / `init_cred` / `root_task_group`) and emits every
derived symbol in the same `0xffffffc080000000` frame. The script aborts
if the three anchors do not agree.

## Probe first (step 0)

`tools/probe-x6873.sh` is a read-only environment & data collector. Run
it BEFORE the derive script — it establishes which derivation path is
viable and captures the raw material for offline analysis:

```sh
adb push ports/x6873/tools/probe-x6873.sh /data/local/tmp/
adb shell sh /data/local/tmp/probe-x6873.sh
```

No root is required (root sections run opportunistically when `su`
works). Every tracefs file it touches is saved and restored; it leaves
no enabled events, registered kprobes or instances behind, and no part
of the exploit runs.

It checks, in order: release gating, SELinux, CPUs/memory/rlimits, the
full tracefs access matrix the engine needs as the shell uid
(`trace_pipe_raw` read; `tracing_on` / kmem event-enable /
`rss_stat` trigger / `instances/` / `kprobe_events` writes), security
sysctls, kallsyms visibility of the exact symbols the port needs,
slabinfo rows, IKCONFIG, a one-shot kmem capture with fork churn
(state restored), and root/manager availability. `--dump-boot`
additionally copies the current-slot boot image into the bundle when
root is available (for offline `recover.py` work, 64-128 MB).

The summary prints one of three verdicts:

- `PATH A` — kallsyms visible + tracefs writable:
  `derive-consts.sh` can run without root.
- `PATH B` — kallsyms hidden but `su` works: run `derive-consts.sh`
  under temporary root (e.g. a GhostLock session).
- `engine BLOCKED` — some shell-uid requirement failed (e.g. tracefs
  writes denied): the engine itself cannot run from adb/Shizuku on
  this build; report the failed lines before investing any time in
  constants.

Send back BOTH the full console output and the printed bundle path
(`x6873_probe_<ts>.tar.gz`).

**Run it WITHOUT `su`.** The engine runs as the unprivileged shell uid,
so the S4 tracefs matrix / S12 engine verdict are only meaningful from
an unprivileged shell. (The 2026-11-12 bundle was captured under
`u:r:ksu:s0`, making those sections root-flavored; probe v1.1 detects
and flags this. The identity/sysctl/slab/config/capture data is
unaffected.)

## Probe results (2026-11-12, bundle `x6873_probe_20261112_195833`)

Device: Infinix GT 30 Pro (X6873), XOS 16 build `BP2A.250605.031.A3` /
`301500018`, security patch 2026-08-01, slot `_b`, `ro.hardware=mt6897`,
KernelSU (Re:Sukisu) + GhostLock app installed, SELinux Enforcing,
`kptr_restrict=2`, `dmesg_restrict=0`, `perf_event_paranoid=-1`.

Findings:

- Release gate: `uname -r` matches the port profile exactly.
- Verdict **PATH B** for the constants derivation: kallsyms hidden — on
  this build zeroed **even for uid 0** (`kptr_restrict=2` blocks every
  reader; the root kallsyms copy shows 0/14 symbols) — but `su` works.
  `derive-consts.sh` v2 lifts `kptr_restrict` for its kallsyms reads and
  restores it right after (trap-guarded).
- Engine environment: 8 CPUs, 6.5 GB available, `max_map_count` 65530,
  all four kmem tracepoints present, `tracing_on` / event-enable /
  `rss_stat`-trigger / `instances` / `kprobe_events` writes all OK —
  but measured as root in this run; re-run the probe unprivileged for
  the authoritative engine verdict. The single `trace_pipe_raw` cpu2
  read failure was a quiet-cpu blocking-read artifact (S9 pulled 1 MB
  from cpu2 with events flowing), not a permission problem.
- The one-shot capture (1.45 MB raw records over 3 CPUs) yielded
  everything derivable offline: 20195 kmem_cache_alloc records decoded
  by a dual-method parser (ring-buffer walker + engine-style pattern
  scan, zero disagreement), the fork path fully visible (29 churn
  forks: task/signal/sighand/mm sites inside a 2 KB `kernel/fork.c`
  cluster), and the posix-timer funnel (139 allocs, 15 pids, one site).
  The low21s and slab sizes are baked into the profile now.
- Runtime kernel image VAs observed at `0xffffffe0xxxxxxxx` (the
  fork.c / cred.c / posix-timers.c / file_table.c call-site cluster is
  internally consistent). Converting them to the linked-image frame
  needs one kallsyms-backed anchor — exactly what the remaining derive
  run provides.
- Kernel config risks for the engine (not constants): KASAN HW tags,
  init-on-alloc, SLUB debug, freelist random + hardened — all present.
  None blocks the derivation; they are engine-stage risk factors on
  race day.

What remains before the first real run: one `derive-consts.sh` v2 run
under `su` (fills `timer_site` + the five data symbols, re-verifies the
baked low21s), one unprivileged probe re-run (engine verdict), then
rebuild + the on-device checklist below.

## Deriving the pending constants

The script needs a root shell on the X6873 itself. Temporary root is
enough — run it right after a GhostLock session, before rebooting:

```sh
adb push ports/x6873/tools/derive-consts.sh /data/local/tmp/
adb shell
su    # GhostLock temporary root
sh /data/local/tmp/derive-consts.sh
```

What it does:

1. Verifies `uname -r` matches the target release and `/proc/kallsyms`
   is readable.
2. Pins the KASLR slide by cross-checking the three measured image
   offsets (aborts on mismatch — that would mean a different kernel
   build).
3. Extracts `panic_on_warn`, `root_user`, `init_user_ns`,
   `init_ucounts`, `init_groups` from kallsyms into the port base frame.
4. Extracts an embedded static arm64 prober that fires one
   `timer_create(CLOCK_THREAD_CPUTIME_ID)` and one `fork()` under the
   `kmem_cache_alloc` tracer, then reads the trace text to recover the
   `do_timer_create` and `dup_task_struct` call sites plus the
   `posix_timers_cache` / `cred_jar` / `task_struct` allocation sizes.
5. Cross-checks the prefilled `SELINUX_STATE_STATIC` against kallsyms.
6. Prints the ready-to-paste profile block for `K61157_plant.c` and the
   slab defines for the `X6873_61157` branch of `plant_core.inc`.

Then rebuild the runner and the app:

```bash
export ANDROID_NDK_HOME=/path/to/ndk
./exploit/build-all.sh          # produces libk61157.so into jniLibs
cd app && ./gradlew :app:assembleRelease
```

The pending guard in `K61157_plant.c` flips off automatically once every
field is non-zero.

## On-device verification checklist

1. Run `tools/probe-x6873.sh` (see "Probe first"); confirm the engine
   verdict is not BLOCKED and note the reported derivation path.
2. Clean boot (no KernelSU patches loaded, stock kernel), Stellar or
   Shizuku running, Shark authorized.
3. Info card shows `CVE-2026-98260-Infinix-6.1.157` (release matched).
4. Before constants are derived, tapping jailbreak must stop with
   `PORT_61157_PENDING` in the log — verify this once on purpose.
5. After pasting the constants and rebuilding: run the jailbreak, watch
   for `PROBE_SLIDE=… aligned=1` and the plant stages (timer reclaim →
   cred spray → fake-cred write → `selinux` → `panic_on_warn`).
6. Manager opens; `su -c id` returns `uid=0(root)`; SELinux state per
   the engine chain (the write targets enforcing directly).
7. Reboot and re-run to confirm the temp-root cycle.
8. If the race never lands on 6.1 (W1-equivalent exhausted, no reclaim),
   capture the full log — that is engine-level evidence, not a constants
   problem (see the caveat below).

## Engine compatibility caveat (read before investing time)

The CVE-2026-98260 engine has only been proven on 6.18/6.12/6.6 GKI
kernels. The 6.1 posix-cpu-timers code is old enough to contain the same
logic, but the slab reclaim behavior that the race depends on
(`posix_timers_cache` sizing, page orders, partial slab churn) differs
per family and cannot be verified from source alone. GhostLock's
CVE-2026-43499 route is the known-working path for X6873; if the 98260
race turns out unreachable on 6.1.157, X6873 support would need engine
work (or the GhostLock engine) rather than constants — that is out of
this port's scope, which was a native Shark-engine profile port.

## References

- GhostLock X6873 kernel profile (measured offsets used here):
  `ghostlock-app/app/src/main/assets/kernel_profiles/6.1.157-android14-11-ga8b0b542991e-ab15601211.conf`
  (github.com/YuKongA/ghostlock-app)
- GhostLock supported-devices list (device/kernel mapping)
- Shark engine: `exploit/src/plant_core.inc` (CVE-2026-98260)
- Device facts: deviceinfohw.ru/devices/item.php?item=126821 (X6873, MT6897)
- Firmware (boot.img source for a host-side derivation alternative):
  hovatek.com/forum/thread-49710.html (X6873 stock ROM collection)
