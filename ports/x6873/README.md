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

**Engine proven on 6.1 — first field run 2026-11-15 (Stellar mode).**
The on-device run (Field run record below; CI APK from Actions run
43673289231) landed the race on `6.1.157-android14`: the timer-free
UAF window was hit in 32-35 ms per attempt with 31/32 slab ownership,
the fake-cred write completed, and the SELinux zero-write round was
in progress where the log paste cuts off. The task→cred write delta
(`0x838`) matched the port constants exactly. **Correction
(2026-11-15 15:31):** the earlier reading that "the SELinux write
resolved to the `...b820` enforcing page" only checked the low bits —
the full address was non-canonical because the KASLR slide was
derived from a one-digit-short `timer_site` constant (see the
slide-derivation field-fix record); the low-bit match was a property
of the low21-preserving garbage, not evidence the target was right.
The former "not yet proven on 6.1" caveat is resolved —
historical text kept at the bottom. The 2026-11-12 probe flags
`CONFIG_KASAN_HW_TAGS=y` and `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`
remain accurate as config facts; the field run shows the engine
tolerates both.

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
| `task_struct.seccomp` (`OFF_TASK_SECCOMP`) | `0x900` (2304) | GL | reference (app-direct seccomp strip; see the app-direct verdict) |
| `SELINUX_STATE_STATIC` | `0xffffffc08225b827` (= enforcing `0x225b820` + base + 7) | GL | final (script re-verifies) |
| cred layout (`caps 0x30 ×5`, `security 0x80`, `user 0x88`, `user_ns 0x90`, `ucounts 0x98`, `group_info 0xa0`) | matches engine template | GL 6.x credential template | final |
| `TIMER_SITE_LOW21` | `0x193300` — the true posix-timers site (bl `kmem_cache_alloc` at `do_timer_create+0xa4`, site `+0xa8`; bl `0x1932fc`). The ~~`0x19feb0`~~ filp-funnel low21 (`__alloc_file+0x2c`) stays retired (v4.1 correction) | S | final |
| `COPY_PROCESS_LOW21` | `0xac148` (29/29 fork-churn allocs, fork.c cluster; re-confirmed 2026-11-14 by kallsyms enclosing `dup_task_struct+0x54` ×2 boots; static parse agrees) | P/S | final |
| `STATIC_TIMER_SITE` | `0xffffffc080193300` (= base `0xffffffc080000000` + linked `0x193300`, inside `do_timer_create` `[0x193258, 0x193858)` — exactly the sibling `+0x94..0xb8` band; bl `0x1932fc` → `kmem_cache_alloc`). **2026-11-15 15:31 fix:** shipped one hex digit short (`0xffffffc08193300`, 15 digits) since `b223d40` — every runtime slide derived from it was garbage; see the slide-derivation field-fix record | S | final (typo fixed) |
| `PANIC_ON_WARN_STATIC` | `0xffffffc08200ae0c` (linked `0x200ae0c`) | S | final |
| `ROOT_USER_STATIC` | `0xffffffc082030780` (linked `0x2030780`) | S | final |
| `INIT_USER_NS_STATIC` | `0xffffffc0820304f0` (linked `0x20304f0`) | S | final |
| `INIT_UCOUNTS_STATIC` | `0xffffffc082032008` (linked `0x2032008`) | S | final |
| `INIT_GROUPS_STATIC` | `0xffffffc082031aa0` (linked `0x2031aa0`) | S | final |
| `TIMER_REQ` / `TIMER_ALLOC` | `0x108` / `0x140` (139 events) | P | final |
| `STATIC_CRED_SITE` / `CRED_SITE_LOW21` | `0xffffffc0800e50d4` / `0xe50d4` — the cred_jar alloc call site (prepare_creds), linked `0xe50d4`, observed as the site mode in the 2026-11-15 field runs; cross-check anchor for the runtime slide vote | S + field | final |
| `STATIC_TASK_SITE` | `0xffffffc0800ac148` — the dup_task_struct alloc call site (linked `0xac148` = `COPY_PROCESS_LOW21`, static parse); second cross-check anchor for the slide vote | S | final |
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

## Engine compatibility caveat (RESOLVED 2026-11-15 — kept for the record)

**Resolution:** the 2026-11-15 field run (Stellar mode) landed the
race on `6.1.157-android14` — `free_seen=1 burst hit=1` in 32-35 ms
per attempt, the fake-cred write done, KASAN HW tags and
init-on-alloc both present and both tolerated. The original caveat,
written before that run:

The CVE-2026-98260 engine has only been proven on 6.18/6.12/6.6 GKI
kernels. The 6.1 posix-cpu-timers code is old enough to contain the same
logic, but the slab reclaim behavior that the race depends on
(`posix_timers_cache` sizing, page orders, partial slab churn) differs
per family and cannot be verified from source alone. GhostLock's
CVE-2026-43499 route is the known-working path for X6873; if the 98260
race turns out unreachable on 6.1.157, X6873 support would need engine
work (or the GhostLock engine) rather than constants — that is out of
this port's scope, which was a native Shark-engine profile port.

## Field run record (2026-11-15, Stellar mode)

First on-device run of the finished chain, launched from the CI APK
(`hoshiyomiX/Shark-Releases` Actions run 43673289231, branch
`x6873-support` @ `eae2c91`), Stellar backend, manager BakaSU
(`com.resukisu.resukisu`, ksud `beta-1-gb4259fe5`, uapi 5, resolved
from the manager APK — `SOURCE=manager-apk`).

Environment facts from the run header:

- `KERNEL=6.1.157-android14-11-ga8b0b542991e-ab15601211` — exact
  profile match; `PROBE_KERNEL` / `PROFILE_61157` / `PROBE_TRACE=yes`
  / `PROBE_OK` all on the first check.
- `BOOT_REASON=kernel_panic` — the previous boot ended in a kernel
  panic (an earlier exploit attempt). The race panic risk is real;
  "clean boot, one attempt, retry after a reboot" (checklist above)
  is the correct operating procedure.

Stage `[1/4]` progress (log excerpt, 12:43:23-12:43:28 device time):

- `[ids] page_alloc=263 page_free=261 pairs=1029` — the tracefs page
  event stream decoded cleanly (the engine observation channel is
  healthy in the shell domain).
- `[base] made=512 best=0xffffff7fc0000000 count=482` — spray base
  page established; KASLR slide derived at runtime
  (`slide=0xefffffd561400000` in the engine frame).
- `[cred] attempt=0 child=10905 ...` — cred located on the first
  attempt (`child cred=0xffffff81ff734180`, target field `+8`).
- Fake-cred write: `stage fake_cred ... attempt=1` → spray
  (`slabs=67 pfns=66 recs=2048 kept=2048`) → trigger child
  (`zombie code=2 status=9` — the deliberate failed-execve path) →
  `free_seen=1 burst hit=1 after 35ms` → `reaped` → `write mode=fake`
  done, with `slab_own=31/32` (31 of 32 objects in the victim slab
  owned by the spray).
- SELinux zero-write: `selinux_state=0xefffff95e365b827` read from
  the fake-cred context, `stage selinux target=0xefffff95e365b820
  mode=zero attempt=1` → second spray round → trigger →
  `free_seen=1 burst hit=1 after 32ms` — the paste ends mid-stage
  (before that round's `reaped`/`write` lines).

Reading of the record:

1. The engine race is **proven on 6.1.157** — the posix-timer page
   was freed on cue, reclaimed by the spray, and the fake-cred write
   completed. The engine-compatibility caveat is resolved.
2. `KASAN_HW_TAGS` + `INIT_ON_ALLOC_DEFAULT_ON` did not prevent the
   reclaim (31/32 ownership, hits in 32-35 ms) — the 2026-11-12 risk
   flags stand as config facts, not as blockers.
3. The `task→cred` write delta observed on device (`0x838`) and the
   SELinux write target low bits (`...b820`, image offset `0x225b820`)
   both match the port constants exactly — the profile row is
   live-validated, not just statically derived.
4. The expected continuation after the paste: the `panic_on_warn`
   clear, the fake-cred sub-object fixups
   (user/user_ns/ucounts/group_info), the child wake, then `[2/4]`
   manager late-load → `[3/4]` su → `[4/4]` manager setup. Confirm
   on-device: BakaSU opens and reports working, `su -c id` returns
   `uid=0(root)`, and a re-run prints `ALREADY_LOADED`.

## One-tap (app-direct) feasibility — verdict (SUPERSEDED 2026-11-16 — see the SHARK app-direct record below)

The recurring question for this port: can the chain run one-tap from
the app's own sandbox (untrusted_app), ghostlock-app style, without
Stellar / Shizuku / ADB? Answer for THIS engine: **no — not without
engine rework.** It is an architecture property, not a constants
problem:

- The CVE-2026-98260 engine is tracefs-architected
  (`exploit/src/plant_core.inc`): the race is observed through
  `/sys/kernel/tracing/per_cpu/cpu*/trace_pipe_raw` kmem/page event
  streams (the `[ids]` pair counting, the `free_seen`/burst watch
  loop) with `tracing_on` control; the KASLR slide is derived from
  the trace-observed timer call site (`observed_site -
  STATIC_TIMER_SITE`); the post-race kernel READ primitive
  (`rd_batch`) registers kprobes (`kprobe_events` + `instances/rd`, a
  `capable` probe with absolute-address fetch args, fired via a
  failing `finit_module` call); `/proc/slabinfo` feeds the `slab_usage`
  stats.
- untrusted_app has no tracefs: this port's own probe v1.2, run from
  an app terminal (`u:r:untrusted_app_30:s0`, 2026-11-12), found
  every S4 tracefs entry MISSING — not denied, invisible. Launching
  this runner app-domain aborts cleanly at preflight with
  `FAIL=probe REASON=trace channel unavailable` (`auto_preflight`) —
  safe, but never one-tap.
- The seccomp side is NOT the blocker: the trigger syscalls
  (timer_create/timer_settime, fork, the failed execve,
  memfd/socketpair) are inside the app seccomp allowlist, and the
  root-child seccomp strip (`thread_info.flags` + `task_struct.seccomp`
  zero writes, `OFF_TASK_SECCOMP=0x900` now documented in the
  constants table) plus a LOCAL ProcessBuilder backend were
  prototyped on the v2.4.1 base (`feat/app-direct`, 2026-11-15) —
  that infra is necessary but not sufficient: the observation channel
  has no app-domain substitute today.

What one-tap on X6873 looks like instead:

1. **Today, zero new code:** ghostlock-app (CVE-2026-43499) ships a
   built-in profile for this exact kernel release (the same GL
   measurements this port's cred/SELinux constants come from;
   `recommend_shizuku = 0`; runtime-confirmed on device — the profile
   records the SELinux write resolving and `getuid() -> 0` via the
   `init_cred` install) and its root child runs the manager
   `ksud late-load`. That is the full no-Shizuku one-tap chain on this
   device — via the futex engine, whose observation channel is pure
   syscalls (no tracefs).
2. **Later, inside Shark:** integrate a syscall-only engine
   (CVE-2026-43499 class; the ghostlock core is Apache-2.0) as an
   app-domain engine behind the LOCAL backend + seccomp-strip infra.
   That is engine work with its own porting checklist; the 98260
   chain stays the Stellar/Shizuku path.

## App-direct SHARK (2026-11-16) — the 98260 engine in the app sandbox

Owner directive: the App-direct execution mode must run the SHARK
engine (CVE-2026-98260), not the 43499 futex engine.  The "engine
rework" this section above called for has landed:

| tracefs dependency (shell flow) | app-domain replacement |
|---|---|
| KASLR slide from trace call-site histogram | FIXED linear-map frame: `slide = (LINEAR_MAP_BASE + KERNEL_PHYS_LOAD) - 0xffffffc080000000` (profile row; `LINEAR_MAP_BASE 0xffffff7fc0000000` = the base the 12:43 run derived at runtime, `KERNEL_PHYS_LOAD 0x40000000`), hard-validated against `APP_EXPECTED_SELINUX 0xffffff800225b820` — the exact address the 2026-11-16 09:04 ghostlock field run wrote SELinux through from the same app sandbox |
| child task/cred from kmem_cache_alloc events | perf SELF-sampling (ghostlock `perf_find_task` mechanism, field-proven on this ROM from untrusted_app, 216/256 votes): the child opens its OWN perf event (pid=0) and getpid-loops; kernel-mode `PERF_SAMPLE_REGS_INTR` registers are voted; two windows must agree |
| victim k_itimer address from the alloc stream | the exec thread creates THE victim in a parent-triggered window ('S' sync) and self-samples it during a `timer_getoverrun(victim)` loop; candidates filtered to the posix_timers_cache stride (`(v & 0x1fff) % 0x140 == 0`), the thread's own task excluded, two windows must agree (fail-closed, retryable) |
| free_seen/burst page gates | TIME-BASED cadence: zombie -> churn1+round1 at t=0, +400ms, +800ms, settle to 1200ms, reap (the 12:43 field cadence: free ~40ms after churn, hit ~35ms after free; phase-1 spray pre-armed so an order-1 alloc is in flight at the free) |
| rd_batch kprobe reads | dropped — every write stays uid-verified through the child report; the seccomp stage uses the documented static offsets |
| /proc/slabinfo stats | optional (silently skipped when unreadable) |

New for the app domain (untrusted_app specifics):

- **Seccomp strip stage**: the app inherits a seccomp filter that blocks
  `finit_module`; two extra zero-write stages (task+0 `thread_info.flags`
  clearing TIF_SECCOMP, task+0x900 `seccomp.mode`) run between fake_uid
  and selinux — the ghostlock W3 writes, field-proven on this device at
  09:04.  The rooted child then forks a filter-free worker that execs
  the root script.
- **Root script (ghostlock model, field-proven 09:04)**: policy fixup
  (netlink flag restore + load_policy loop) -> `ksud late-load` ->
  module watch -> per-run `ksu.log` markers (`[+] KernelSU module
  loaded` / `[!] KernelSU module not loaded`) -> enforcing restore.
  The markers are the app verdict AND the runner [2/4] fallback
  (`/proc/modules` goes dark for untrusted_app once enforcing returns).
- **iomem cache**: the root script dumps /proc/iomem into the app dir;
  the next run's preflight parses the `Kernel code` base and refuses to
  plant if the kernel physical load ever moves (fail-closed against
  future KASLR drift).
- **Frame guard**: the preflight aborts before touching any timer unless
  `SELINUX_STATE_STATIC + slide - 7 == APP_EXPECTED_SELINUX`.

Residual risks (accepted; the field loop iterates):

- The perf victim leak is a NEW mechanism class (self-sampled timer
  syscall registers).  Round-5 (2026-11-16 16:12) returned V=0(n=0) six
  windows in a row while the getpid window always found the task
  pointer; the round-5 fix samples three vehicles (the getoverrun pair
  + timer_gettime + a dormant timer_settime re-arm) and prints each
  window's raw histogram (`[perf] victim leak w<n> ... raw=[...]`) so
  the next log pins the failure class; a systematically wrong winner
  would show as a distinct signature in the log (see the 16:12
  field-fix record at the end of this file).
- Without the trace burst gate, reaping after a reclaim miss (a system
  allocation stealing the freed order-1 page) can panic — the same
  one-attempt-per-clean-boot discipline applies.

Expected app log on success: `Starting CVE-2026-98260 SHARK (app-direct)`
-> `[app] frame: ... selinux_target=0xffffff800225b820` -> `[perf] task
self-sample top=...` -> `[+] stage fake_cred ... mode=fake` ->
`[+] stage fake_uid` -> `stage tif_flags` -> `stage seccomp` ->
`[+] stage selinux target=0xffffff800225b820` -> `PLANT_CRED_OK` /
`PARKED=1` -> `[child] woke uid=0` -> root script markers -> `MODULE_LOADED`
-> `DONE` -> the app prints `KernelSU module loaded` + `RESULT=SUCCESS`
and opens the manager.

## App-direct SHIPPED (2026-11-15) — the 43499 channel is in the APK (SUPERSEDED 2026-11-16: replaced by the SHARK app-direct above; libghostlock.so and the GLK1 asset were removed from the APK by the owner's directive — the vendored core stays under third_party/ as the reference for the perf/root-script models)

Option 2 above landed. The release APK now offers an "Execution mode"
selector (and auto-selects it when no Stellar/Shizuku backend runs):

- Engine: the Apache-2.0 ghostlock C++ core vendored at
  `third_party/ghostlock-core/`, built by `exploit/build-ghostlock.sh`
  into `jniLibs/arm64-v8a/libghostlock.so` (NDK API 35, C++23, PIE;
  24/24 production units host-compile clean).
- Profile: `app/src/main/assets/ghostlock_profiles/6.1.157-android14-11-ga8b0b542991e-ab15601211.glk1`
  (GLK1 v2 wire, 1955 bytes, sha256
  `414bb2e1eddc55593a8e7a42d5dd329a7752bcf3ceccf3739f7ed579970dc497`),
  exported with the upstream profile-core exporter and decode-verified
  against the vendored native reader: release exact, task.cred 0x838,
  task.real_cred 0x830, task.seccomp 0x900, selinux_enforcing 0x225b820,
  init_cred 0x2031aa8, route tcp_zerocopy, frontend RootChild,
  backend Cve2026_43499 — ALL MATCH the constants table above.
- App flow: `MainActivity.runGhostlockDirect()` (ProcessBuilder spawn,
  `GHOSTLOCK_KSUD` pinned to the selected manager's libksud.so via
  PackageManager, work dir `filesDir/ghostlock/run`; verification through
  a live `/proc/modules` read while permissive, falling back to the per-run
  `ghostlock/run/ksu.log` load markers — see the 2026-11-16 record below).
  Design doc: `docs/app-direct.md`.
- The 98260 Stellar/Shizuku path is untouched and remains the default
  when a backend is running.

## References

- GhostLock X6873 kernel profile (measured offsets used here):
  `ghostlock-app/app/src/main/assets/kernel_profiles/6.1.157-android14-11-ga8b0b542991e-ab15601211.conf`
  (github.com/YuKongA/ghostlock-app)
- GhostLock supported-devices list (device/kernel mapping)
- Shark engine: `exploit/src/plant_core.inc` (CVE-2026-98260)
- Device facts: deviceinfohw.ru/devices/item.php?item=126821 (X6873, MT6897)
- Firmware (boot.img source for a host-side derivation alternative):
  hovatek.com/forum/thread-49710.html (X6873 stock ROM collection)

## Field-fix record: 2026-11-15 decoy-node write encoding

Two consecutive field runs (12:43 and 14:23, CI build eae2c91) landed the
race cleanly (`free_seen=1 burst hit=1` both times) but died at the write
phase: the 12:43 boot ended in `kernel_panic` (seen as the 14:23 run's
`BOOT_REASON=kernel_panic`), and the 14:23 run died inside the first
plant's reap, before the `[+] reaped` line could print.

Root cause, verified against the actual kernel bytecode (boot.img Image
disassembly, anchored on the on-device kallsyms; every profile constant
re-checked and confirmed exact — `selinux_state`, `panic_on_warn`,
`root_user`, `init_user_ns`, `init_ucounts`, `init_groups`, node offset
`k_itimer+0x78` from `posix_cpu_timer_set`'s `add x1, x23, #0x78`):

- `cleanup_timers()` (called from `release_task+0xe8`, i.e. the reap that
  the engine waits for after the spray) loops `timerqueue_del()` over the
  dead task's cpu-timer queue and zeroes `node+0x20` after each erase.
- This ROM's `timerqueue_del()` compiles the `RB_EMPTY_NODE` check into a
  `brk #0x800` WARN-with-resume. The old fake-cred encoding laid the cred
  *on* the stale node with `parent_color = node`, which is exactly the
  `RB_EMPTY_NODE` state: every fake write tripped the WARN (fatal when
  `panic_on_warn=1`) and the `node+0x20` zeroing clobbered the overlaid
  cred's `ucounts` (NULL) for the runs that survived the WARN.

The fix (`exploit/src/plant_core.inc`, shared by every engine):

- **Decoy node**: the stale node at `V+0x78` stays a pure rb node
  (`parent_color = A`, `rb_left = target`, `rb_right = 0`) and points at
  a separate fake cred elsewhere in the reclaimed page. `RB_EMPTY_NODE`
  is never true, so the WARN cannot fire; `rb_erase`'s left-only branch
  writes `A` into `task->cred`; the erase's `change_child` dirt lands on
  `cred->suid/sgid` only; the cleanup's `node+0x20` zeroing hits the
  decoy, so `cred->ucounts` survives intact.
- **Single-erase exit**: `cred->usage = 0` and `cred->uid/gid = N` make
  `rb_next(N)` walk `N -> A -> (usage 0) -> NULL`, so the cleanup loop
  terminates after the one erase and never touches the cred slot.
  `usage=0` also means `put_cred()` can never free the fake cred.
- **Transient dirt**: `uid/gid` keeps the node address and `suid/sgid`
  keeps the write target until the woken child runs `setuid(0)` (full
  caps) — no kernel-side deref of either happens in that window, so the
  old `fake_uid` repair stage is removed (one plant cycle fewer).
- **panic_on_warn pre-stage**: the runner executes as the shell
  (Stellar/Shizuku uid 2000) where `/proc/sys/kernel/panic_on_warn` is
  readable pre-exploit; when it reads 1 a zero-mode write clears it
  before the chain (zero-mode erases never warn, so the pre-stage is
  itself safe). The decoy makes the fake write WARN-free regardless.

The write mechanics were re-validated end to end against the transcribed
`timerqueue_del`/`rb_erase`/`rb_next` bytecode with a deterministic
simulation (1 erase, 0 WARNs, no writes outside the reclaimed page /
`task->cred` / the dead task's queue head; `euid=0`, `ucounts` and
`security` intact). All eight engines pass `gcc -fsyntax-only` and the
k61157 full compile.

## Field-fix record: 2026-11-15 15:31 KASLR slide derivation (one-digit-short timer_site)

The third field run (15:31, CI build `69f0c62`) got further than both
12:43/14:23 runs: the fake-cred plant completed end to end
(`free_seen=1 burst hit=1 after 89ms` → `reaped` →
`write mode=fake target=…dac078`), the fake cred was installed, and the
run died at the START of the SELinux zero-write round — the log cuts at
`[dbg] plant1 spray round=1 at free (no churn)` and the next boot shows
`BOOT_REASON=kernel_panic` (the `free_seen`/`burst hit` lines print only
after the round completes, so their absence means the kernel died inside
the window).

Root cause — a one-digit-short profile constant, not the trace channel:

- `K61157_plant.c` shipped `timer_site = 0xffffffc08193300` (15 hex
  digits) since `b223d40`. The base convention is
  `0xffffffc080000000 + 0x193300 = 0xffffffc080193300` (16 digits) — the
  README's own constant-table formula never matched the pasted value.
- The engine derives the runtime slide as
  `observed_site - STATIC_TIMER_SITE`. The observed sites were CORRECT
  text addresses all along (reconstructed from both boots' logs:
  `0xffffffd169593300` / `0xffffffd9b6593300`, true slides
  `0x1161400000` / `0x19ae400000` — tens of GiB, consistent with the
  VA48 vmalloc KASLR span). Subtracting the 15-digit constant turned
  every slide negative-huge (`0xefffffd561400000`, `0xefffffddae400000`).
- The garbage slide poisoned everything downstream at once: the
  SELinux/panic_on_warn zero-write targets (`SELINUX_STATE_STATIC +
  slide - 7 = 0xefffff9e3065b820`, non-canonical → the round-2 erase
  faulted → panic) and the fake cred's `user`/`user_ns`/`ucounts`/
  `group_info` pointers (`STATIC + slide`, garbage → any
  `prepare_creds()`/`set_user()` on the fake cred would fault too).
- The low21 checks could not catch it: both sites share low21
  `0x193300`, so the garbage slides were still "2 MiB aligned", and the
  `...b820` low bits of the SELinux target still matched the enforcing
  offset — which is why the 12:43 record misread the target as
  "resolved to the enforcing page".

Fix (`exploit/src/K61157_plant.c` + shared `exploit/src/plant_core.inc`,
host unit test `ports/x6873/tools/test_derive_slide.c` driver):

1. **`timer_site` corrected to `0xffffffc080193300`** (the missing digit
   restored). With the 15:31 field site this yields the convention-frame
   slide `0x1936400000` and a canonical SELinux target
   `0xffffffd9b865b820`.
2. **Slide derivation hardened (all engines):** `scan_timer_allocs` now
   histograms every passing `call_site` and reports the MODE (the exec
   thread emits ~2048 records from the single `do_timer_create` site;
   a stray low21 colliding record can no longer be first-match
   promoted). `derive_slide()` validates every candidate (2 MiB
   alignment, positive, < 16 TiB vmalloc-span bound, canonical
   `SELINUX_STATE_STATIC + slide`) and votes three independent anchors:
   the timer site mode plus the NEW leak-phase anchors
   `STATIC_CRED_SITE` (`0xffffffc0800e50d4`, prepare_creds site) and
   `STATIC_TASK_SITE` (`0xffffffc0800ac148`, dup_task_struct site).
   A single bad constant now loses the vote or fails the run closed
   (`FAIL=… slide …`, no write) instead of firing — the unit test
   proves the old typo alone would have been outvoted 2:1.
3. **Fail-closed write gates:** every slide-derived `stage_write` target
   is checked (`require_kptr_target`) before planting; a non-canonical
   target aborts with a clear tag instead of panicking the device.
4. **Child uid normalization (second latent bug):** the decoy encoding
   leaves `uid/gid/suid/sgid` = the node address, but `wait_child_main`
   still exited when `uid != 0` — after the slide fix the woken child
   would have died at that check and never run the late-load. The fake
   path now runs `setresgid(0)` + `setuid(0)` first (normalizing the
   transient ids exactly as the decoy design intends) and only refuses
   if `setuid(0)` itself fails.

Diagnostics added for the next field run: `[dbg] plant1 timer site
hist:` (the full call-site histogram), `[slide] anchor … ok=…` lines,
`[+] slide=… votes=…`, and `cred_site=…(n=…) task_site=…(n=…)` on the
`[cred]` line. Expected continuation on device: round 1 as today, then
`[slide] anchor timer … ok=1` → `selinux` stage with a canonical
`0xffffff…b820` target → `panic_on_warn` (if 1) → child wake with
`setresgid(0)=0` / `setuid(0)=0` → `[2/4]` late-load. All seven
plant_core engines pass `gcc -fsyntax-only`; the k61157 host build plus
`ports/x6873/tools/test_derive_slide.c` (19 assertions, field vectors; build: `gcc -D_GNU_SOURCE -pthread -I exploit/src -o /tmp/t ports/x6873/tools/test_derive_slide.c `scripts/test_derive_slide.c` (19 assertions, field vectors)`scripts/test_derive_slide.c` (19 assertions, field vectors) /tmp/t`) all pass.

## Field-fix record: 2026-11-15 16:28 wake-path BUG_ON (fake_uid repair restored)

Fourth field run (16:28, CI build `4d82822`) validated the slide fix
completely: all three anchors agreed on `slide=0x1a9b600000` (votes=3)
in both rounds, the selinux zero-write round completed for the first
time (`free_seen=1 burst hit=1 after 29ms` -> `reaped` ->
`write mode=zero target=0xffffffdb1d85b820`, canonical), and
`panic_on_warn` read 0 (no stage needed). The log ends at
"cred writes landed, waking child" with no child line after it and the
next boot shows `BOOT_REASON=kernel_panic` - the kernel died at the
wake.

Root cause - a design flaw introduced by the decoy commit (`69f0c62`),
triggered by its own child-side normalization:

- The decoy encoding leaves the fake cred's `uid/gid` = the node
  address and removed the kernel-side `fake_uid` repair plant, planning
  for the woken child to run `setuid(0)` instead ("full caps, before
  anything else").
- But the fake-cred task runs with `task->cred` = the fake cred while
  `task->real_cred` still points at the original shell cred, and every
  `set*id()` goes through `commit_creds()`, which opens with
  `BUG_ON(task->cred != old)` - an unconditional kernel panic on this
  path. The pre-decoy chain never called `set*id()` in the fake child,
  so the flaw lay dormant until this run reached the wake for the first
  time.

Fix (`exploit/src/plant_core.inc`):

1. **`fake_uid` repair plant restored** (kernel-side): after the
   panic_on_warn stage, one zero-mode write to `A+8` zeroes uid/gid in
   the fake cred, making it a complete uid-0 credential before the
   wake - exactly the pre-decoy mechanism, retargeted from the overlaid
   node to the separate decoy cred (`fc.A + CRED_UID_OFF`).
2. **No `set*id()` in the fake child anymore** (the panic): the child
   reports, late-loads and parks without ever mutating its creds. The
   `system()` fork for late-load gets a consistent copy
   (`copy_creds` -> `prepare_creds` copies `task->cred` and gives the
   forked task `cred == real_cred`), so the root work in the forked
   child may call `set*id` safely.
3. The parent's success check is now `uid == 0 && euid == 0` (a failed
   repair can no longer pass as "euid 0 with garbage uid").
4. `derive_slide()` tie-break cosmetics: on full ties the winner stays
   the anchor with the most records instead of flipping to the last
   candidate (the 16:28 log showed "votes=3 (task n=1)").

Expected log on the next clean-boot run: round 1 (fake_cred) and round
2 (selinux) as in the 16:28 run, then `stage panic_on_warn` only if the
sysctl reads 1, then the NEW `stage fake_uid target=<A+8> mode=zero`
round, then `[child] woke uid=0 euid=0`, `[+] child report ...`,
`PLANT_CRED_OK`, `PARKED=1`, `[fake] child ... late-load then park`,
`LATE_LOAD_CMD=...` and the runner's `[2/4]` -> `MODULE_LOADED` ->
`[3/4]` -> `[4/4] DONE`. All seven engines pass `gcc -fsyntax-only`;
the slide unit test (19 assertions) still passes.

## Field-fix record: 2026-11-15 16:58 round-3 window panic (stage reorder + panic forensics)

Fifth field run (16:58, CI build `2621e54`) — the owner's verdict
(2026-11-16): the log's truncated line is the kernel-panic point and
the phone rebooted. The run had passed every prior milestone: slide
unanimous (`0x2498c00000`, votes=3), round 1 fake-cred landed in 33 ms
(`A=0xffffff81019cc800`, target `task+0x838`), round 2 selinux zero
landed in 38 ms (`0xffffffe51ae5b820`), `panic_on_warn` read 0 (no
stage), and round 3 (`stage fake_uid target=0xffffff81019cc808
mode=zero`) staged — then the log cut at `[dbg] plant1 spray round=1
at free (no churn)` and the kernel panicked.

Root cause — a pre-reap window panic, not the repair write:

- `main()` runs `setvbuf(stdout, NULL, _IONBF, 0)`, so every `logf`
  line hits the fd the moment it is printed; the truncation point is
  therefore the EXACT panic boundary (the 14:23 run proved the same
  property in reverse: its log stopped right before `[+] reaped` when
  the reap itself panicked).
- The reap (the `waitpid` that fires `cleanup_timers` -> the erase ->
  the write) happens only AFTER `[+] plant1 free_seen=1 burst hit=1`
  prints. That line never appeared — so the round-3 erase NEVER
  EXECUTED. The panic happened in the free->hit window: the third
  socket spray in flight, the round-3 zombie unreaped and inert, the
  fake child still blocked in `read(3)`.
- Mechanism correction for the 15:31 record above: that run shows the
  SAME signature (cut at `spray round=1 at free`, pre-hit), so its
  selinux erase never ran either — the "non-canonical erase target
  faulted" mechanism was wrong. Both window panics were asynchronous
  derefs of accumulated exploit state; in 15:31 the garbage slide had
  poisoned the round-1 fake cred's `user`/`user_ns`/`ucounts`/
  `group_info` pointers on a live blocked task. The slide fix was
  still the right fix — it cured the cred pointers — but via the
  async-deref class, not the erase.
- What the 16:58 run left in that class: the fake cred on the blocked
  child still carried `uid/gid` = the node address (a kernel pointer
  VALUE, `0xffffff81019cc8xx` as a uid_t) — the decoy encoding keeps
  it as the `rb_next` walk-up key — and it would have stayed garbage
  through the entire third race until the repair write.
- The repair cannot be fused into round 1 (geometry proof against the
  transcribed bytecode): `parent_color` must equal `A` (it is both the
  value installed into `task->cred` and the walk parent), so the
  erase's change-child dirt always lands on `A+8` (uid/gid) or
  `A+0x10` (suid/sgid); every two-iteration variant either moves the
  garbage between those fields or sends `rb_next`'s descend path into
  live task memory (`task+0x848`), and the two-children erase path is
  the sim's WALK HAZARD. The decoy v2 + one kernel-side repair write
  is the only safe shape.

Fix (`exploit/src/plant_core.inc`, shared by every engine):

1. **Stage reorder — repair first, selinux last.** The chain is now
   `fake_cred` -> `fake_uid` (immediately after the install) ->
   `selinux` (last, immediately before the wake) -> optional
   `panic_on_warn`. The garbage-uid cred now exists for ONE round
   instead of two, and the final system-wide mutation lands as late as
   possible. The erase mechanics per round are byte-identical to the
   field-proven ones (sim-verified: fake mode since 69f0c62, zero mode
   since 4d82822).
2. **Panic forensics.** `dump_pstore_tail(50)` runs FIRST in `main`
   (right after the pid line): when a boot follows a kernel panic, the
   previous run's console-ramoops tail — panic header, PC/LR, call
   trace — is printed at the top of the new run's log. One attempt per
   clean boot makes the next run the diagnostic for the previous one's
   panic; a recurrence is pinned instead of guessed. Missing/unreadable
   pstore logs one line and continues (shell uid 2000 often cannot
   read pstore).
3. **The fake child exits after the late-load** instead of parking
   forever. The parked child kept a task with garbage `suid/sgid` in
   the table for the rest of the boot; exiting removes it while the
   fake cred itself survives (`usage=0`, `put_cred` 0->-1 never frees)
   inside the page held by the PARENT's socket spray — the parent still
   parks and holds the page. The report was already consumed over pipe
   4, and the parent never waits this child, so the exit leaves at
   most one harmless zombie. (The ColorOS HOOKS_GATE flow keeps its
   worker-fork + park shape — its gate handshake needs the child
   alive.)

Validation: `sim-decoy.py` extended to the reordered 3-round chain —
fake_cred 1 erase / 0 WARNs / install intact, fake_uid 1 erase /
0 WARNs / uid+gid zeroed / install intact, selinux 1 erase / 0 WARNs /
enforcing zeroed / cred state intact, and NO writes outside the
reclaimed pages / `task->cred` / the dead task's queue head. All eight
engines pass `gcc -fsyntax-only`; the k61157 full compile passes; the
slide unit test still passes.

Expected log on the next clean-boot run: `[pstore] ...` lines first
(if the previous boot ended in a panic, its trace is printed here),
then round 1 (`fake_cred`) as before, then the NEW ORDER — `stage
fake_uid target=<A+8> mode=zero` landing, THEN `stage selinux
target=<...b820> mode=zero` — then `cred writes landed, waking child`,
`[child] woke uid=0 euid=0`, the child report, `[fake] ... one-shot
late-load`, `[fake] late-load done; child exiting`, `PLANT_CRED_OK`,
`PARKED=1` and the runner's `[2/4]` -> `MODULE_LOADED` -> `[3/4]` ->
`[4/4] DONE`. If anything panics again: reboot, run once more on the
clean boot, and read the `[pstore]` block at the top — it contains the
previous panic's call trace.

## Field record: 2026-11-16 09:04 app-direct SUCCESS — verdict false-negative fixed

Sixth field run (09:04:42, CI build `a954550`, app-direct 43499 engine,
manager BakaSU). The exploit itself was PERFECT — every stage green on
the first attempt of every round:

- W1 SELinux permissive: route `done=1 calls=1 success=1 clean=1/1` —
  first TCP-zerocopy entry attempt.
- W2 root: `child uid = 0` / `child is root!` (perf task 236/256 votes).
- W3 seccomp: TIF_SECCOMP + mode writes both `clean=1/1`; probe
  `finit_module = 0x16` (errno 22 = EINVAL — the syscall executes,
  seccomp does not block it); `child seccomp fully bypassed`.
- Handoff: child alive, root shell worker pid 32451, script fd open;
  root script ran the policy fixup + `ksud late-load` chain.
- Engine verdict: `[+] KernelSU ready` (its handoff probe found the
  `[+] KernelSU module loaded` marker in the per-run `ksu.log`) and
  `enforce=1 (enforcing)` — SELinux restored by design.
- `exploit exit=0`. Owner confirmed on-device: the jailbreak works
  (BakaSU active).

But the app log ended `KernelSU module not loaded` -> `RESULT=FAIL` —
verdict: FALSE NEGATIVE, not an exploit failure.

Root cause: `MainActivity.readDeviceState(local=true)` verified the
module with a direct `/proc/modules` read from the app sandbox. Once the
root script restores SELinux enforcing (which a correct run always
does), `untrusted_app` cannot read `/proc/modules` (EACCES) — the exact
wall the engine's own `handoff_probe.cpp` documents
("untrusted_app loses /proc/modules once enforcing is restored"),
which is why the engine watches the per-run `ksu.log` markers instead.
The app did not, so every successful app-direct run self-reported FAIL
after enforcing came back. Side effects: `launchManager()` and the
soft-reboot path (both gated on `rc == 0 && active`) never ran.

Fix (`MainActivity.kt` only; engine and root script untouched):

1. `readDeviceState(local=true)` verifies through two channels: a live
   `/proc/modules` read (works while permissive, before the module-init
   re-enforce) OR the per-run `ghostlock/run/ksu.log` markers
   (`[+] KernelSU module loaded` / `[+] KernelSU already loaded`),
   guarded to the current boot (a late-loaded LKM does not survive
   reboot — mtime vs `now - elapsedRealtime()`, 60 s grace);
   `[!] KernelSU module not loaded` counts as a definitive failure.
2. `runGhostlockDirect()` rotates the previous run's `ksu.log` to
   `ksu.log.prev` before spawning the engine — per-run evidence, one
   generation kept for field debugging; stale markers can never
   satisfy a new run's verdict.
3. After engine exit the verdict polls the evidence up to 12 s
   (1 s interval) before concluding not-loaded — the engine can exit
   before a slow late-load writes its marker; rc != 0 or the failure
   marker stops the poll immediately.
4. The failure message now names the evidence file, so a field log
   distinguishes "module genuinely not loaded" from "check failed".

Expected log on the next run: `exploit exit=0` -> (normally instant,
up to 12 s worst case) `KernelSU module loaded` -> `RESULT=SUCCESS`,
and the manager opens automatically (or the soft reboot runs when
enabled). The engine lines are unchanged.

## 2026-11-16 14:35 field run — perf EACCES on a clean enforcing boot (exit 13)

Build a9eda16 (versionCode 93), MANAGER=BakaSU. The preflight fix worked
(`PROBE_TRACE=skip(app-domain)` -> `PROBE_OK`, frame validated, selinux
target matched). The run then died at the perf gate:

```
[-] perf_event_open failed errno=13 (app domain needs it)
[-] perf self-sampling unavailable; the app engine cannot leak addresses - refusing
PLANT_FAIL (enforce=unknown)      <- /system/bin/getenforce unreadable from
exploit exit=13                     untrusted_app under enforcing (2nd signal)
```

Root cause — an architectural ordering difference between the two engines:

* The 98260 app port (d9c98a6) needs its kernel-address leaks BEFORE its
  first write: the victim k_itimer `V` (payload geometry) and the child
  task (cred install target) both come from perf kernel-register
  self-sampling. Under enforcing, SELinux denies `perf_event_open` for
  `untrusted_app` -> the whole chain is blocked before it starts. The
  `perf_event_open` attrs are byte-identical to the 09:04-proven
  ghostlock `perf_find_task`, so the delta is the SELinux mode, not the
  syscall.
* The 43499 engine (09:04) is SELinux-first BY DESIGN —
  `cve_2026_43499_backend.cpp`: "W1: disable SELinux before task
  discovery". Its pre-W1 leak is KernelSnitch (futex-hash timing — no
  privilege, no perf, works under enforcing), and every perf-dependent
  stage (victim spawn, W2/W3) runs AFTER W1 made the device permissive.
  That is why 09:04 succeeded on the same app sandbox.

Fix — the 43499 W1 becomes the clean-boot unlock pre-stage (98260 stays
the app-direct engine per the owner directive):

1. `third_party/ghostlock-core`: `PYB110_UNLOCK_ONLY` stops the 43499
   pipeline right after W1 (no victim spawn, no perf, no handoff) and
   prints the `UNLOCK_OK` marker. `libghostlock.so` + the GLK1 profile
   asset ship in the APK again; the CI builds the engine fresh.
2. `MainActivity.runSharkDirect`: before spawning the 98260 runner, run
   the unlock stage (`libghostlock.so --load-prebuilt-profile`, LOCAL
   backend, 240 s watchdog). `UNLOCK_OK` -> continue; a miss -> continue
   anyway and let the 98260 preflight fail-close (the 14:35 behavior is
   preserved as the diagnostic path).
3. k61157 app preflight logs the leak environment before the perf gate:
   `[app] perf diag: paranoid=<n> enforce=<n> ctrl_useronly_errno=<n>`
   (sentinels -999 unreadable / -998 unparseable). A user-space-only
   control event (exclude_kernel=1) separates the paranoid DAC check
   from the SELinux denial in the field log.

Expected log on a clean enforcing boot (round 4):
`[unlock] CVE-2026-43499 W1: ...` -> ghostlock W1 lines ->
`UNLOCK_OK: SELinux permissive; perf self-sampling unblocked` ->
`[unlock] SELinux permissive; continuing with the 98260 SHARK engine` ->
the 14:35 sequence from `PROBE_KERNEL` onward, now with
`[app] perf diag: ... enforce=0` and the perf gate passing ->
the normal stage chain (map item 4+ of the round-2 plan).

Notes:
* A failed 98260 run after a landed unlock leaves the device permissive
  until the next success (script restores) or reboot — retrying in the
  same boot is warm by design; that is the field-loop procedure anyway.
* `ksu_root_owned()` under enforcing cannot read /proc/modules and
  defaults to "not owned" — the unlock stage always attempts W1 on a
  clean boot; the already-rooted-same-boot corner keeps the runner's
  own ALREADY_LOADED path.

## Field-fix record: 2026-11-16 16:12 round-5 clean-boot run — victim leak V=0 (multi-vehicle vote)

Build 56768ff (versionCode 94), MANAGER=BakaSU, clean boot
(`BOOT_REASON=kernel_panic`, no `ALREADY_LOADED` — the 09:04 LKM is
gone with the reboot).  The round-4 validation map landed exactly as
designed up to the predicted frontier:

* unlock W1 7.8 s (`UNLOCK_OK` at T+7806 ms) — the 14:35 perf-EACCES
  class is gone: `[app] perf diag: paranoid=-1 enforce=0 ...` and the
  perf gate passes; the round-3 fix is PROVEN in the field.
* the child task self-sample agreed on the first try (1232/17 then
  1260/5); `cred_field_target = task+0x838`.
* the 98260 app-direct chain then died at the plant1 victim leak — the
  exact "perf victim leak agreement" frontier the round-2 plan predicted:

```
[+] stage fake_cred target=0xffffff82e9dd2db8 mode=fake attempt=1
[perf] victim leak top=0(0) agreed=0 task=0xffffff816bc992c0 cand2=0(0) cand3=0(0)
[-] plant1 victim leak not trusted (V=0 agreed=0); retryable     (x6, exit 13)
```

Diagnosis:

* Window A (getpid) found the exec thread's task pointer every time
  (`task=` changes per attempt = fresh exec threads; the identical
  values in the instant app-retry are task_struct slab reuse, not a
  second bug) — so the perf event, the register sampling, the parse and
  the direct-map range check all work in the app sandbox.
* `TIMER_ALLOC=0x140` is the family constant (probe bundle + the 6.6
  sibling row), so the stride filter is not obviously wrong — but the
  evidence line only ever printed the stride-FILTERED candidates, and
  with the k_itimer absent everything printed 0(0).  Whether the victim
  pointer (a) never sat in a sampled register during the getoverrun
  loop, (b) sat there under a different stride, or (c) the loop
  fast-failed — could not be distinguished from the log.  The fix must
  both raise the catch odds and make the next log decisive.

Fix (this build, versionCode 95):

1. `app_leak_victim` now samples FOUR vehicle windows around the same
   victim timer: the original getoverrun pair (byte-identical), plus
   `timer_gettime` (read-only, a longer posix-cpu-timer body) and a
   `timer_settime` dormant 3600 s re-arm (the disassembly ground truth
   holds the k_itimer in x23 across the whole posix_cpu_timer_set
   body).  Both new vehicles are normal healthy-timer kernel paths; no
   stale/fake node is ever touched, so the RB_EMPTY_NODE WARN class
   cannot fire here.
2. Every window prints its full evidence, even when the vote refuses:
   `[perf] victim leak w<n> <go|gt|st> top=<filtered>(n) hn=<hist size> err=<failures> raw=[<unfiltered top-3>]`
   — the raw histogram was the missing tuning evidence.
3. The vote requires a stride-passing candidate to be the filtered
   top-1 of >= 2 windows with >= 1000 votes in each (the 1232-vote
   getpid task pointer is the proven single-register signal level);
   the summary line carries `wins=k/4 floor=1000`.

Round-6 read of the next log:

* `hn=0` on a window -> the event produced no kernel-pointer samples at
  all; `err>0` -> the loop fast-fails (timer validity class); a raw
  top-1 with a huge count that fails the 0x140 stride -> the real
  k_itimer under a different stride (fix TIMER_ALLOC); a recurring
  non-timer pointer winning -> entry-path noise (raise the floor or
  exclude it).
* Success looks like: `w1 go top=V(n>=1000)` + `w3 gt top=V(...)` ->
  `agreed=1 wins=2/4` -> `[+] plant1 victim report: V=<k_itimer>` ->
  the decoy layout -> the race -> `PLANT_CRED_OK` -> `[child] woke
  uid=0` -> the root script -> `MODULE_LOADED` -> `RESULT=SUCCESS`.
* The panic path is unchanged: one attempt per clean boot; pstore
  stays EACCES (errno=13) in the app domain so the previous panic's
  trace remains unavailable there.

## Field-fix record: 2026-11-17 07:14 round-6 run — vehicle syscalls 100% failed (err == iters)

Build 9642aa3 (versionCode 95), MANAGER=BakaSU, `BOOT_REASON=reboot`.
The unlock pre-stage exited 0 within the same second without any W1
output (`unlocked=false`), yet SELinux was permissive by the shark
preflight (`[app] perf diag ... enforce=0`, `PLANT_FAIL
(enforce=Permissive)`) — the warm-retry note above (a previous attempt
in the same boot already landed W1) is the expected explanation; this
build now prints `enforce before/after` around the stage so the next
log shows it directly. The runner chain then reached the fake-cred
stage; all three attempts x four vehicle windows reported
`V=0(n=0) agreed=0 wins=0/4 floor=1000`, exit 13.

Diagnosis (the round-5 evidence lines earned their keep):

* Every window printed `err` equal to the FULL iteration budget
  (300000/300000/250000/150000): ALL vehicle syscalls returned < 0.
  The round-5 fallback `SYS_timer_getoverrun 437` is openat2 on
  aarch64 (the correct number is 109), so the getoverrun pair called
  openat2 with the timer id as dirfd. The gt/st windows used the
  CORRECT numbers (108 gettime / 110 settime) and still failed 100%:
  the bionic `timer_t` handle is not the raw kernel timer id, so the
  raw syscalls never addressed the victim timer at all. The
  posix-cpu-timer bodies (x23 = k_itimer) never executed — the vote
  never received real input, and the recurring raw top-1
  (0xffffff821c286300, 18-32 hits, residue 0x80 mod 0x140) is a
  failure-path object, not k_itimer evidence.

Fix (this build, versionCode 96):

1. The app-domain victim timer is created and armed through the RAW
   aarch64 syscalls (107 create / 110 settime) and the KERNEL timer id
   is kept; `app_leak_victim` receives that raw id and all three
   vehicles call 108/109/110 on it directly — immune to bionic's
   timer_t wrapper policy and to header gaps.
2. `perf_self_sample` prints the first failing errno per window
   (`eno=`): EINVAL vs EBADF vs 0 becomes a one-look signal.
3. The sampling ring is drained into the histogram every 512
   iterations with a wrap-safe record copy (`perf_hist_drain` /
   `perf_ring_copy`): with working vehicles the windows generate far
   more samples than the 128 KiB ring holds, and round-5's
   parse-once-at-the-end would wrap and desync.
4. The app logs `enforce before/after` around the unlock stage.
   The vote (>= 2 windows x >= 1000 votes), the stride filter
   (TIMER_ALLOC=0x140) and the window layout are unchanged — the
   round-5 design never had real input.

Round-7 read of the next log:

* `eno=0` + `err=0` on the vehicle windows and a stride-passing top-1
  with large counts agreeing across >= 2 windows -> `agreed=1
  wins>=2/4` -> `[+] plant1 victim report: V=<k_itimer>` -> decoy ->
  race -> `PLANT_CRED_OK` -> `[child] woke uid=0` -> root script ->
  `MODULE_LOADED` -> `RESULT=SUCCESS` — the round-4b validation gap
  closes.
* `eno=22` (EINVAL) with the raw id -> the id itself is rejected by
  the kernel; re-check the raw-create path before touching the vote.
* `eno=0` but the raw top-1 still fails the 0x140 stride with a huge
  count -> the real k_itimer under a different stride (the round-5
  map's TIMER_ALLOC branch; 0x140 stays probe-proven until that log
  says otherwise).
* `enforce before=0` on a CLEAN boot would mean the unlock
  short-circuit deserves its own look (before=1 -> after=0 with
  UNLOCK_OK is the normal clean-boot path).
* The panic path is unchanged: one attempt per clean boot; pstore
  stays EACCES (errno 13) in the app domain.

## Round-7 record (08:03:35 WITA Nov 17, fad25ac vc96, warm same-boot)

Map branch taken: `eno=0` + `err=0` with a stride-passing top-1
agreeing across windows -> `agreed=1 wins=2/4` - the round-6
raw-timer fix is FIELD-VALIDATED (V=0xffffffb07d570000, n
5127-5407, the same victim object re-identified by all five stage
cycles; `eno` never moved off 0). The chain then ran further than
ever before: victim report -> decoy -> all five stage writes
(`fake_cred` install at A=V+0x800, `fake_uid` zero at A+8,
`tif_flags`, `seccomp`, `selinux`) -> "cred writes landed" -> wake.
FAIL at the final readback: `[child] woke uid=10706 euid=10706` -
the pristine app values - so the live child's task->cred never
became A: the fake_cred install did not take effect on the live
child task. Exit 13 (`cred`), no module load.

Three log-honesty traps this round exposed (the first two are
fixed in vc97):

1. `[+] child report stage=2 ... setuid(0)=0 errno=0
   resuid=0/0/0` was NOT a successful setuid. On the fake path the
   report is sent immediately after the uid/euid sample and the
   set*id fields were still the memset zeros; no setuid ever ran
   (the fake path forbids it - commit_creds BUG_ON, the 16:28
   precedent). vc97 marks unattempted fields -1.
2. The unlock stage on a warm boot printed `unlocked=false` +
   "permissive not confirmed" because SELinux was already
   permissive at entry (enforce before=0): nothing to flip,
   nothing to confirm, and the fail-closed warning that followed
   was noise (perf was not blocked: paranoid=-1, and the chain
   proceeded). vc97 counts permissive-at-entry as unlocked and
   says so in the log.
3. The duplicated tail (08:04:03-08:04:04, identical T=28316ms
   and identical churn deltas) is the app log layer replaying the
   runner buffer, not a second attempt; `exploit exit=13` fired
   once. `holder=t61269-hold` is a compile-time prctl name
   (plant_core.inc park_forever), not a thread id.

## Round-8 map (read of the next log, vc97)

The vc97 child report ends with `probe finit=<e> seccomp=<r>/<e>`
(two read-only probes taken at the wake, before the uid check):

* `finit=1` (EPERM): the seccomp filter still enforces -> the
  tif_flags zero (task+0) did NOT land. Together with the pristine
  uid this means the child-task writes are not landing at all ->
  the plant write/trigger or the leaked task address is the
  suspect, not the cred encoding alone.
* `finit=9` (EBADF) + `seccomp=2/0`: tif_flags LANDED, the
  seccomp-struct zero (task+0x900) did NOT.
* `finit=9` + `seccomp=-1/22`: tif+seccomp both LANDED; only the
  fake_cred install missed -> the install encoding (mode=fake,
  parent_color=A walk-forced variant) is the round-9 suspect.
* `[child] woke uid=0 euid=0` -> the install landed this time:
  PLANT_CRED_OK -> root script -> MODULE_LOADED -> RESULT=SUCCESS
  (the round-4b validation gap closes).
* uid wakes as a huge garbage value (not 0, not 10706): the
  install landed but the fake_uid zero (A+8) missed -> audit that
  store. The offset itself is corroborated (ghostlock core model:
  CRED_UID_OFF=8, caps 0x30 x5, security 0x80 - the same layout
  family the X6873 profile measured), so a miss there points at
  the store, not the offset.
* `setuid(0)=-1 errno=-1 resuid=-1/-1/-1` on the fake path is the
  new honest "not attempted" marker; probe fields at -1 mean n-a
  (warm/shell paths).
