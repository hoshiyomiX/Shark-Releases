# Infinix GT 30 Pro (X6873) — CVE-2026-98260 port

## Status

**Constants FINAL — port complete on the constants side (2026-11-15).**
The X6873 chain is wired end to end (runner feature, plant, app
integration) and the profile row in `K61157_plant.c` is fully
populated. Every per-build constant was derived OFFLINE by static
parsing of three stock boot.img images (live-slot dump + SF
16.3.0.150SP09 + SF 16.3.0.160SP02): the kernel Image is byte-identical
across all three, so the constants are stable with zero drift between
firmware versions, and the 12/12 on-device baseline cross-check
(2026-11-12 measurements) matched exactly. The fail-closed guard stays
in the plant for future rows: an incomplete profile still refuses to
run and prints `PORT_61157_PENDING` instead of touching the kernel.

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
4. Clear `panic_on_warn` (`0xffffffc08200ae0c` + slide).
5. Fix the fake cred's `user/user_ns/ucounts/group_info` fields to point
   at `root_user` / `init_user_ns` / `init_ucounts` / `init_groups`
   (`0xffffffc082030780` / `0xffffffc0820304f0` / `0xffffffc082032008` /
   `0xffffffc082031aa0`, each + slide; struct offsets `0x88/0x90/0x98/0xa0`
   already match the 6.1 credential template).
6. Wake the root child, run `ksud late-load` for the selected manager.

## Constants

Sources: `GL` = GhostLock X6873 kernel profile for this exact release
(measured on device, 33/33 boots), `P` = offline analysis of the
2026-11-12 probe bundle (`x6873_probe_20261112_195833`, build
`301500018`, slot `_b`), `S` = static parse of the stock boot.img
kernel Image (2026-11-15, three images, zero drift; pipeline:
`tools/extract_kernel.py` + `tools/parse_x6873_stock.py`), `D` =
on-device derivation via `tools/derive-consts.sh` (alternative route,
still useful for a future firmware).

| Constant | Value | Source | Status |
|---|---|---|---|
| release | `6.1.157-android14-11-ga8b0b542991e-ab15601211` | GL | final |
| `OFF_TASK_CRED` | `0x838` (`task_struct.cred = 2104`) | GL | final |
| `task_struct.real_cred` | `0x830` (2096) | GL | reference |
| `SELINUX_STATE_STATIC` | `0xffffffc08225b827` (= enforcing `0x225b820` + base + 7) | GL | final (script re-verifies) |
| cred layout (`caps 0x30 ×5`, `security 0x80`, `user 0x88`, `user_ns 0x90`, `ucounts 0x98`, `group_info 0xa0`) | matches engine template | GL 6.x credential template | final |
| `TIMER_SITE_LOW21` | `0x193300` — the true posix-timers site (bl `kmem_cache_alloc` at `do_timer_create+0xa4`, site `+0xa8`; bl `0x1932fc`). The ~~`0x19feb0`~~ filp-funnel low21 (`__alloc_file+0x2c`) stays retired (v4.1 correction) | S | final |
| `COPY_PROCESS_LOW21` | `0xac148` (29/29 fork-churn allocs, fork.c cluster; re-confirmed 2026-11-14 by kallsyms enclosing `dup_task_struct+0x54` ×2 boots; static parse agrees) | P/S | final |
| `STATIC_TIMER_SITE` | `0xffffffc08193300` (= base `0xffffffc080000000` + linked `0x193300`, inside `do_timer_create` `[0x193258, 0x193858)` — exactly the sibling `+0x94..0xb8` band; bl `0x1932fc` → `kmem_cache_alloc`) | S | final |
| `PANIC_ON_WARN_STATIC` | `0xffffffc08200ae0c` (linked `0x200ae0c`) | S | final |
| `ROOT_USER_STATIC` | `0xffffffc082030780` (linked `0x2030780`) | S | final |
| `INIT_USER_NS_STATIC` | `0xffffffc0820304f0` (linked `0x20304f0`) | S | final |
| `INIT_UCOUNTS_STATIC` | `0xffffffc082032008` (linked `0x2032008`) | S | final |
| `INIT_GROUPS_STATIC` | `0xffffffc082031aa0` (linked `0x2031aa0`) | S | final |
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

### Static parse route (the source of the final constants)

The constants above were derived offline from the stock boot.img, not
on the device. The pipeline now lives in `tools/`:

1. `tools/extract_kernel.py <boot.img> <out.bin>` — Android boot image
   v0-v4 (optional MTK pre-header), gzip/lz4/zstd/raw kernels; verifies
   the arm64 Image magic `ARMd` at +0x38. X6873 stock images are
   ANDROID v4 with an lz4-legacy kernel (magic `0x184C2102`).
2. `tools/parse_x6873_stock.py parse <out.bin> <out.json>` — anchored
   kallsyms discovery (this build's `kallsyms_relative_base` is
   `0xffffffc008000000`, NOT the `0xffffffc080000000` needle recover.py
   searches for, and ~300 KB of foreign .rodata sits between names and
   markers, so the recover.py walk-back fails on this build — the
   anchored scan finds the strictly-nondecreasing s32 offset array
   instead), a full BL-scan call map of `do_timer_create` /
   `copy_process` / `dup_task_struct`, and BTF struct sizes via
   `ports/v2505a/recover.py`.
3. `tools/parse_x6873_stock.py diff <a.json> <b.json> [out.json]` —
   STABLE/DIFFERS verdict per constant across two firmware versions.

Evidence (2026-11-15): three stock images (live-slot + SF 150SP09 + SF
160SP02) yield a byte-identical kernel Image (sha256
`ca8f54a3c8f3570fd02549281060e12d436f131ce08dc2825978f154fcf70ee0`,
35,637,760 bytes) — 15/15 constants STABLE, zero drift between
16.3.0.150SP09 and 16.3.0.160SP02; 12/12 device-measured baseline
constants matched exactly. The KASLR slide on the reference device is
`0x2052a00000` under the `0xffffffc080000000` convention frame
(`0x20caa00000` against the true static base `0xffffffc008000000`);
both are 2 MiB-aligned and offsets are slide-invariant, so the plant
constants do not change either way.

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

What remains before the first real run: nothing on the constants side —
they are final (static parse above). Remaining: one `adb shell` probe
run (the authoritative engine verdict for uid 2000), then rebuild +
the on-device checklist below.

First derive/probe run findings (2026-11-12, evening) — see also run #2 below:

- derive v2 under `su`: `kptr_restrict` lift worked and all three
  anchors + slab sizes were read, but Android mksh computes `$(( ))`
  in 32-bit signed ints — v2's `% 4294967296` died with `zero
  divisor` and the empty slide then compared EQUAL across the anchors
  (fail-open). v3+ keeps every value as a signed int32 representative
  of its mod-2^32 class. The embedded prober also failed
  (`timer_create`); v3+ no longer depends on it for the derivation.
- probe v1.1 without `su` from the on-device terminal: died with
  `FATAL: no writable work directory` — that terminal's context cannot
  write `/data/local/tmp` (DAC `other` has no write bit there) and the
  v1.1 fallback candidates (`$PWD`, `/tmp`) are never writable on
  Android. probe v1.2 probes candidates with a real write, adds
  `TMPDIR`/`HOME`/script-dir/`/sdcard`, reports why each candidate was
  rejected, and notes when the running uid is neither root nor the
  shell uid 2000 (app-domain terminals measure the wrong uid for the
  S4 matrix — prefer `adb shell`).

Second derive run findings (2026-11-12 ~22:00, derive v3) + the
22:07 probe bundle:

- derive v3 under `su`: the kptr lift, the three-anchor slide pin
  (0x52A00000, 2 MiB-aligned — int32 arithmetic confirmed working on
  mksh) and the mandatory-symbol checks all PASSED. It aborted at the
  v3 site disambiguation: `do_timer_create` is at linked offset
  `0x193258` and no `0x19feb0`-low21 candidate lies within 16 KiB.
  That killed the ±16 KiB assumption and motivated v4.
- Cross-boot combo analysis (offline, from the two bundles + the
  measured symbol): the 19:58 bundle's runtime funnel/copy sites
  (0xffffffe0d2d9feb0 / 0xffffffe0d2aac148) differ by exactly
  `0x2F3D68` mod 2^32, and the linked candidates must satisfy
  `L_t - L_c = 0x2F3D68` with `L_t = 0x19feb0 + a*2MiB`,
  `L_c = 0xac148 + b*2MiB` ⇒ `a = b+1`. The k=0 timer candidate
  (0x19feb0, +51 KiB from `do_timer_create` — the v3 trap) forces
  `b = -1` (impossible), so the funnel is at `0x39feb0` (a=1, 2 MiB
  above `do_timer_create` — GKI/LTO function reordering) with the
  copy site at `0xac148` (b=0, the fork.c cluster).
  **v4.1 CORRECTION (2026-11-14, lifted kallsyms + capture re-read):
  this analysis was WRONG.** The 19:58 "139 timer allocs from 15
  pids" were 320B **filp** events at `__alloc_file+0x2c` (linked
  `0x39feb0`) — the GhostLock file-spray funnel, not posix timers
  (that capture contains ZERO 264B-req events). `0x39feb0` and the
  `0x2F3D68` delta describe the filp funnel; the true posix_timers
  site is inside `do_timer_create` (sibling ports: `+0x94..0xb8`).
  The v4.1 derive gates the site on the do_timer_create window.
- probe v1.2 (22:07 bundle, `x6873_probe_20261112_220755`): ran from
  the MT Manager terminal as `u:r:untrusted_app_30:s0` (uid 10044) —
  the v1.2 workdir fallback worked (bundle under the app's TMPDIR)
  and the uid note fired correctly. In that context tracefs is not
  even VISIBLE (all S4 entries MISSING, not denied) and
  `kallsyms.root.txt` came back fully zeroed (no `su` grant from that
  app context). Expected for an untrusted app — but it is NOT the
  engine's context either: the authoritative engine verdict still
  needs one probe run from `adb shell` (uid 2000, `u:r:shell:s0`),
  where tracefs is typically readable/writable on MTK Android 16.

## Deriving the pending constants

The script needs a root shell on the X6873 itself. Temporary root is
enough — run it right after a GhostLock session, before rebooting:

```sh
adb push ports/x6873/tools/derive-consts.sh /data/local/tmp/
adb shell
su    # GhostLock temporary root
sh /data/local/tmp/derive-consts.sh
```

What it does (v4):

1. Verifies `uname -r` matches the target release and `/proc/kallsyms`
   is readable.
2. Pins the KASLR slide by cross-checking the three measured image
   offsets (aborts on mismatch — that would mean a different kernel
   build), then prints EVERYTHING kallsyms-only up front (slide,
   `do_timer_create` / `dup_task_struct` linked offsets, the five data
   symbols, selinux delta) — so even a later abort leaves a usable
   console.
3. Reads the slab sizes from `/proc/slabinfo`.
4. Trace window (primary site source): the embedded static prober
   (**v4.1: its timer_create syscall number is FIXED — it called 222,
   the x86_64 number, which is mmap on arm64; every run failed with a
   bare `PROBE_TIMER_FAIL`. Now nr 107, patched in the embedded blob
   and disassembly-verified**), then a passive 3 s all-pid window
   with forced fork churn from the script itself. Any
   `kmem_cache_alloc` record with the right `bytes_req` gives the
   exact call site — symbol form
   (`sym+0xNN/0xMM`, resolved against a kallsyms copy taken inside
   the lifted `kptr_restrict` window), `0x…` form, or bare 16-hex
   form (kernel pointer printing carries no `0x`), all via the
   pinned slide. The low21 must match the bundle-baked value (build
   identity gate); fresh `bytes_alloc` must match the bundle.
5. Kallsyms enclosing-function fallback (when no trace record):
   candidates `low21 + k*2MiB` inside `[_text, _etext]`; for each,
   the enclosing function comes from the kallsyms copy (windowed
   scan, ~fast); a site is accepted ONLY when exactly ONE candidate's
   enclosing symbol matches the known family (timer:
   `*timer_create*` / `*posix_timer*` / `*alloc_posix*`; copy:
   `*dup_task*` / `*copy_process*` / `*alloc_task*` / `*task_struct*`).
   Ambiguous or empty aborts with a full candidate dump for offline
   analysis. Trace and fallback must agree when both resolve.
6. Prints the ready-to-paste profile block with per-site provenance
   (source: trace/family, enclosing symbol) and the slab defines.

Why v4 exists (device run #2, 2026-11-12 ~22:00): v3's slide pin
WORKED on device (three anchors agreed, 2 MiB-aligned — the mksh
int32 fix is proven), but its site disambiguation assumed the
posix-timer alloc site sits within ±16 KiB of `do_timer_create`.
The device run measured `do_timer_create` at linked offset
`0x193258` and aborted: no candidate with low21 `0x19feb0` within
16 KiB. Cross-boot analysis (below) shows the assumption was
structurally wrong — the funnel is 2 MiB away. v4 replaces the
proximity assumption with trace-primary + enclosing-family
resolution.

Then rebuild the runner and the app:

```bash
export ANDROID_NDK_HOME=/path/to/ndk
./exploit/build-all.sh          # produces libk61157.so into jniLibs
cd app && ./gradlew :app:assembleRelease
```

The pending guard in `K61157_plant.c` flips off automatically once every
field is non-zero.

### Verifying the derive console offline (analysis side)

When a v4 console arrives, run `tools/verify-derive-v4.sh` over it
before pasting anything:

```sh
tools/verify-derive-v4.sh <console.txt> [kallsyms-copy]
```

It re-parses every constant mechanically, checks each value against
the v4.1 expectations (timer site inside the `do_timer_create`
window, copy `0xac148`, the filp-funnel low21 `0x19feb0` exclusion,
`do_timer_create` `0x193258`; the old `0x39feb0`/`0x2F3D68`
predictions are retired as filp-funnel facts), verifies
single-slide consistency
(3-anchor agreement and an independent candidate-uniqueness ladder
when the kept kallsyms copy is supplied), diffs the paste block
against the console lines, and emits the canonical profile row itself
on success. Exit codes: `0` VERIFIED (paste the emitted row) · `2`
INCOMPLETE (usable subset, gaps listed — pending data symbols or an
aborted site resolution) · `1` FAILED (a hard check violated — the
evidence contradicts the cross-boot model; do not paste). The tool is
mock-hardened on the analysis side (`scripts/mock-verify-test.sh`,
six synthetic console/kallsyms scenarios, 48 assertions).

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
