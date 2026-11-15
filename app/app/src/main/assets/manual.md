# Shark User Manual

Shark drives the on-device 98260 exploit as the shell user through Stellar or Shizuku, then loads the manager LKM. On first use, finish the authorization first, then run the one-tap jailbreak.

> Shark currently supports Oplus-family devices on the 6.18.21, 6.12.69, 6.12.38, 6.12.58, 6.12.23, 6.6.118 and 6.6.127 kernels, plus the Infinix GT 30 Pro (X6873) on 6.1.157 — always matched against the full `uname -r`; unmatched devices are told they are not supported.

## Quick start

1. Install the ROOT manager of your choice first (KernelSU / FinaSU / KernelSU Next / BakaSU / SukiSU Ultra); **ci builds of KernelSU Next are not supported yet**.
2. Start and activate **Stellar (recommended)** or **Shizuku** using **wireless debugging or adb**, and grant Shark permission.
3. Back on the Shark home page tap **One-tap jailbreak** and wait for the success log; `DONE`, `SU_ID_RC=0` and `uid=0(root)` are the authoritative markers.
4. On success the manager opens automatically; with the matching switches on, the security popups are also disabled and **SUSFS** (6.18/6.12 lines; 6.12 uses `libsusfs_guard_lkm_612.so`) or **VFS** (6.18.21 only) is loaded.
5. If the log shows **MODULE NOT LOADED**, just tap jailbreak again — no reboot needed.
6. Every app start checks for updates: Gitee Releases first, GitHub as fallback; a new version pops a dialog, downloads in-app and hands the APK to the system installer. You can also tap **Check for updates** manually on the About page.

## Permissions and preparation

- **Stellar first, Shizuku fallback**: when both are present Stellar is used; only if Stellar is unavailable does it fall back to Shizuku.
- **The manager must be installed first**: ksud is not bundled — at runtime it is executed in place from the manager APK's `lib/arm64`.
- **Prefer a clean boot before running**; 6.18.21, 6.12.69, 6.12.38, 6.12.58, 6.12.23, 6.6.118, 6.6.127 and 6.1.157 are each an independent chain, and the app selects by exact `uname -r`.

## One-tap jailbreak flow

**preflight** (kernel release / trace channel) → **98260 UAF** (fake cred / SELinux zero write) → **one-shot ksud late-load from the cred child** → wait for the module and su → **finish** (ksud install, unload the kernel guard, SUSFS, VFS, screenshot restore, launch the manager).

Every kernel version has its own K source file and `libk<version>.so`; there is no source-level reuse — the shared engine lives in `plant_core.inc`. vivo devices (6.12.23 / 6.12.58 vivo builds / 6.6.127) zero the tracepoint funcs slots used by `vr.ko` before waking the root child; 6.6.127 also zeroes the `sched_process_exit` slot. 6.12.58 OS7 (`gdd6fd5c98918`) and 6.6.127 additionally go through the `hooks_defend` load-gate bypass: locate the module, one zero write to unlock, publish the khs whitelist, then load the KO in-process.

- **Fast path**: the plant takes ~2–3 s and the whole flow ~4–9 s; a missed reclaim costs a few extra seconds — normal variance.
- **After any failed chain**: the pages held by the plant are handed to a holder and you can simply tap again in the same boot; do not manually kill or reap the holder.

## Feature notes

- **Home**: ROOT manager dropdown and flow switches (VFS shows for 6.18 only; vivo V2505A hides the three anti-root items; 6.6.118 / 6.6.127 show no SUSFS/VFS/hot switch; 6.12.58 OS7 hides SUSFS but keeps the hot switch; 6.1.157 keeps the anti-root popup switch and soft reboot while SUSFS/VFS/ Dynamic Switching stay hidden). The info card shows the kernel version and the automatically selected exploit.
- **Logs**: the live streaming log of the current run.
- **History**: every run saves a `.log`; tap to read the full text, swipe an entry left for the **Export** button and share it with other apps.
- **About**: version, check for updates, source / community / issue entries, the AboutLibraries dependency list (per-library versions and licenses, tap for details) and the offline open-source license texts bundled with the APK (GPL-3.0, NOTICE, Apache-2.0, MIT, GPL-2.0, MPL-2.0).
- **Extras → Droidspaces support** (6.18.21 only): tapping **Download module** fetches the latest `Droidspaces-LKM` release on GitHub, then downloads the module zip after confirmation; the file is saved to `Download/Shark/` — flash it afterwards from the KernelSU manager (Modules → Install). The module is not bundled in the APK.
- **ROOT manager → Dynamic Switching** (6.18.21 / 6.12.69 / 6.12.38 / 6.12.58 / 6.12.23; not 6.6.118): run it once per clean boot after selecting it; `libksud_universal.so` loads the universal KSU LKM (initially KernelSU, with the dual-KMI 6.18/6.12 KO embedded). After loading, Extras gains **Manager hot switch**: switch between KernelSU / KernelSU-Next / BakaSU / SukiSU / FinaSU without rebooting or re-jailbreaking; the target manager app reopens after the switch.

## Troubleshooting

| Log | Action |
| --- | --- |
| `PROBE_FAIL` / `kernel mismatch` | The current kernel is not on the support list (only exact `uname -r` matches against 6.18.21 / 6.12.69 / 6.12.38 / 6.12.58 / 6.12.23 / 6.6.118 / 6.6.127 / 6.1.157). |
| `MANAGER` / `KSUD_MISSING` | Install the matching manager APK first, then run. |
| `STALE_PLANT` | A previous plant is still running; wait for it to become a holder, then retry. |
| `PLANT_FAIL` | The plant keeps its holder and exits; just retry in the same boot. |
| `LATE_LOAD_FAIL` | The module did not appear within the deadline; check the ksud output in the log, confirm the manager version matches, then retry. |
| `PORT_61157_PENDING` | Only possible if a profile row is incomplete — the shipped 6.1.157 row is fully populated, so this never fires on stock firmware. |
| Kernel panic / reboot | Inherent risk of the 98260 race; reboot and run again. |

## How each chain runs

- **6.18.21** → `libk61821.so`; **6.12.69** → `libk61269.so` (the two OTA builds pick call sites by uname).
- **6.12.38 (PLR110)** → `libk61238.so`; **6.12.58 (PLZ110 / V2505A OS6/OS7)** → `libk61258.so`; **6.12.23 (V2505A)** → `libk61223.so`.
- **6.6.118 (PKJ110 / PKH110 / Pads)** → `libk66118.so` (two OTA builds pick call sites by uname); KMI android15-6.6.
- **6.6.127 (vivo X200 Ultra / PD2454)** → `libk66127.so`; KMI android15-6.6, via the vivo hooks_defend load-gate bypass.
- **6.1.157 (Infinix GT 30 Pro / X6873)** → `libk61157.so`; KMI android14-6.1. The per-build constants were derived offline from the stock boot.img (the kernel Image is byte-identical across 16.3.0.150SP09 and 16.3.0.160SP02), and the engine observes the KASLR slide at runtime — see `ports/x6873/README.md`. Normal mode needs a manager APK that carries an `android14-6.1` LKM; verify the module actually loads on this Transsion build before relying on it.
- All chains match by **exact `uname -r`**; an unmatched device gets a not-supported toast when tapping jailbreak.
- Every chain runs in place from the app's native library dir (`nativeLibraryDir`); the children's cwd/HOME/TMPDIR stay inside the app filesDir — nothing is deployed to or written in `/data/local/tmp`, and ksud is executed in place from the installed manager APK. SUSFS is supported on the 6.18/6.12 lines (6.12 uses `libsusfs_guard_lkm_612.so`); 6.6.118 / 6.6.127, 6.12.58 OS7 and 6.1.157 do not offer it; the VFS switch is 6.18-only.
- For systems research on your own devices only.
