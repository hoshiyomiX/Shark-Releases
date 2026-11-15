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

## One-tap (app-direct) feasibility — verdict

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
