#!/system/bin/sh
# probe-x6873.sh - environment & data probe for the Shark CVE-2026-98260
# Infinix GT 30 Pro (X6873) port.
#
# Purpose: collect on the device everything the Shark engine and the X6873
# constants derivation need, WITHOUT running any part of the exploit:
#
#   S1  identity gating (uname release, build props)
#   S2  SELinux state
#   S3  CPUs / memory / rlimits (engine spray prerequisites)
#   S4  tracefs access matrix - the engine runs as the shell uid and needs
#       to READ per_cpu/cpuN/trace_pipe_raw and WRITE tracing_on, the
#       kmem event enable files, the rss_stat trigger file, instances/
#       and kprobe_events (plant_core.inc enable_events/rd_setup)
#   S5  security sysctls (kptr_restrict, dmesg_restrict, ...)
#   S6  /proc/kallsyms visibility of the exact symbols the port needs
#   S7  /proc/slabinfo rows (cred / task_struct / timer caches)
#   S8  kernel config (IKCONFIG) - the CONFIG_* lines that matter
#   S9  one-shot kmem trace capture with full save/restore (fork churn
#       only; raw + text buffers saved for offline call-site analysis)
#   S10 root availability (su), root managers, /data/adb
#   S11 boot partitions (sizes, current slot; --dump-boot is optional)
#   S12 verdict summary + tar.gz bundle
#
# Safety: every tracefs file touched is saved and restored; no persistent
# kprobes are left registered, no instances are left behind, no events are
# left enabled. Nothing outside the output directory is written. This is a
# data collector, not the exploit: no posix timers are raced, no kernel
# memory is written.
#
# Usage (adb shell; root NOT required - root sections are optional):
#     adb push probe-x6873.sh /data/local/tmp/
#     adb shell sh /data/local/tmp/probe-x6873.sh
#
# When it finishes, send back BOTH:
#     1. the full console output (copy-paste - it is self-sufficient for
#        the first analysis pass), and
#     2. the bundle /data/local/tmp/x6873_probe_<ts>.tar.gz
#
# Options:
#     --dump-boot   with root: copy the current-slot boot partition into
#                   the bundle for offline recover.py work (adds 64-128 MB)
#
# Portability: pure POSIX shell (mksh + toybox on Android; also runs under
# dash/bash for offline mock tests). No awk, no sed, no python.

VERSION="1.2"
# v1.2 (2026-11-12, after the first real non-root run): the work-dir
# discovery used '[ -w /data/local/tmp ]', which fails in app-domain
# terminals (DAC 'other' has no write bit there) and the fallback list
# ($PWD, /tmp) is never writable on Android either -> "FATAL: no
# writable work directory". v1.2 probes candidates with a REAL write
# (create + remove a per-uid temp file), adds TMPDIR / HOME / the
# script's own directory / /sdcard to the candidate list, reports WHY
# each candidate was rejected, and prints the chosen work dir + uid
# up front. Also flags runs from a uid that is neither root nor the
# shell uid 2000 (the S4 matrix is only authoritative for uid 2000).
RELEASE="6.1.157-android14-11-ga8b0b542991e-ab15601211"

# --- overridable inputs (also used by the offline mock tests) ---
TR="${X6873_TRACEFS:-/sys/kernel/tracing}"
TRDBG="${X6873_TRACEFS_DBG:-/sys/kernel/debug/tracing}"
KS="${X6873_KALLSYMS:-/proc/kallsyms}"
SLABINFO="${X6873_SLABINFO:-/proc/slabinfo}"
CONFIGGZ="${X6873_CONFIGGZ:-/proc/config.gz}"
BYNAME="${X6873_BYNAME:-/dev/block/by-name}"
CPUDIR="${X6873_CPUDIR:-/sys/devices/system/cpu}"
MEMINFO="${X6873_MEMINFO:-/proc/meminfo}"
LIMITS="${X6873_LIMITS:-/proc/self/limits}"

UNAME_R="${X6873_RELEASE:-$(uname -r 2>/dev/null)}"

DUMP_BOOT=0
for a in "$@"; do
    case "$a" in
        --dump-boot) DUMP_BOOT=1 ;;
        *) : ;;
    esac
done

# --- output location ---
TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo manual)"
WORK="${X6873_WORK:-}"
if [ -z "$WORK" ]; then
    # Probe candidates with a REAL write (create + remove), not '[ -w ]':
    # access(2) misleads in app-domain terminals and behind FUSE.
    _UID="$(id -u 2>/dev/null || echo 0)"
    _SD="$(dirname "$0" 2>/dev/null)"
    _REJ=""
    for d in "${TMPDIR:-}" "${HOME:-}" /data/local/tmp "$_SD" "$PWD" /sdcard /tmp; do
        [ -n "$d" ] || continue
        if [ ! -d "$d" ]; then _REJ="$_REJ $d(missing)"; continue; fi
        if ( : > "$d/.x6873_probe_w.$_UID.$$" ) 2>/dev/null; then
            rm -f "$d/.x6873_probe_w.$_UID.$$" 2>/dev/null
            WORK="$d/x6873_probe_$TS"
            break
        fi
        _REJ="$_REJ $d(nowrite)"
    done
fi
if [ -z "$WORK" ]; then
    echo "FATAL: no writable work directory found"
    echo "  rejected:$_REJ"
    echo "  HINT: app-domain terminals (Termux etc.) usually cannot write"
    echo "  /data/local/tmp - run from 'adb shell' (uid 2000) or with su,"
    echo "  or set X6873_WORK=<writable dir> and re-run."
    exit 1
fi
mkdir -p "$WORK" 2>/dev/null || { echo "FATAL: cannot create $WORK"; exit 1; }
echo "probe v$VERSION workdir: $WORK (uid $(id -u 2>/dev/null || echo unknown))"
LOG="$WORK/probe.log"

# --- logging helpers (no tee dependency) ---
lg() {
    printf '%s\n' "$*" >> "$LOG" 2>/dev/null
    printf '%s\n' "$*"
}

N_OK=0; N_FAIL=0; N_SKIP=0
ok()   { N_OK=$((N_OK + 1));   lg "[ OK ] $*"; }
bad()  { N_FAIL=$((N_FAIL + 1)); lg "[FAIL] $*"; }
skip() { N_SKIP=$((N_SKIP + 1)); lg "[SKIP] $*"; }
info() { lg "       $*"; }
sec()  { lg ""; lg "===== $* ====="; }
kv()   { lg "KV $1"; }

# --- tracefs state save / restore ---
SSTATE="$WORK/tracefs_state.txt"
: > "$SSTATE" 2>/dev/null

state_save() {
    # state_save <file> - remember the current value of a tracefs file
    [ -f "$1" ] || return 1
    _v="$(cat "$1" 2>/dev/null)" || return 1
    printf '%s\t%s\n' "$1" "$_v" >> "$SSTATE"
}

state_restore() {
    [ -s "$SSTATE" ] || return 0
    _n=0
    while IFS="$(printf '\t')" read -r _p _v; do
        [ -n "$_p" ] || continue
        [ -f "$_p" ] || continue
        if printf '%s\n' "$_v" > "$_p" 2>/dev/null; then
            _n=$((_n + 1))
        fi
    done < "$SSTATE"
    lg "[rest ] tracefs state restored ($_n file(s))"
}

wr() {
    # wr <file> <payload> - write attempt; returns 0 on success
    ( printf '%s\n' "$2" > "$1" ) 2>/dev/null
}

# --- verdict accumulators (consumed by S12) ---
V_RELEASE=0; V_RAW_READ=0; V_TRON_WRITE=0; V_EV_WRITE=0; V_TRIG_WRITE=0
V_INST=0; V_KPROBE=0; V_KMEM_EVENTS=0; V_CPUS=0; V_KSYM_VISIBLE=0
V_ROOT=0; V_ROOT_UNKNOWN=1; V_SLAB=0; V_CONFIG=0

lg "x6873-probe v$VERSION - Shark CVE-2026-98260 port data collector"
lg "workdir: $WORK"
lg "note: read-only probe; tracefs toggles are saved and restored"

# ---------------------------------------------------------------- S0 self
sec "S0 runtime"
lg "date   : $(date 2>/dev/null)"
lg "uid    : $(id 2>/dev/null || echo unknown)"
_sec_ctx="$(cat /proc/self/attr/current 2>/dev/null)" && \
    lg "domain : $_sec_ctx" || lg "domain : (unreadable)"
lg "argv0  : $0"

# The S4 tracefs matrix and the S12 engine verdict are only authoritative
# for the ENGINE (which runs as the unprivileged shell uid) when the probe
# itself runs unprivileged. Under su every access check passes as root and
# proves nothing about the shell uid (observed in the 2026-11-12 bundle,
# which ran under u:r:ksu:s0 and still printed a shell-uid verdict).
PROBE_UID=$(id -u 2>/dev/null || echo unknown)
V_ROOT_RUN=0
if [ "$PROBE_UID" = "0" ]; then
    V_ROOT_RUN=1
    bad "probe is running as ROOT: the S4 tracefs matrix and the S12 engine"
    bad "verdict below reflect ROOT access, not the shell uid the engine"
    bad "uses. Re-run WITHOUT su (adb shell sh ...) for the engine verdict;"
    bad "this run is still fine for S1/S5-S11 data collection."
else
    if [ "$PROBE_UID" = "2000" ]; then
        ok "probe runs as the shell uid (2000): S4/S12 reflect the engine's view"
    else
        ok "probe runs unprivileged (uid $PROBE_UID)"
        info "NOTE: uid is not 2000 (adb shell). If this terminal is an app"
        info "domain (Termux etc.), the S4 tracefs matrix below measures the"
        info "APP uid, not the shell uid the engine runs as - prefer"
        info "'adb shell sh /data/local/tmp/probe-x6873.sh' for the verdict."
    fi
fi

# ------------------------------------------------------------ S1 identity
sec "S1 identity (release gating)"
lg "uname -r : $UNAME_R"
lg "uname -a : $(uname -a 2>/dev/null)"
lg "/proc/version : $(cat /proc/version 2>/dev/null || echo unreadable)"
if [ "$UNAME_R" = "$RELEASE" ]; then
    V_RELEASE=1
    ok "release matches the X6873 port profile ($RELEASE)"
else
    bad "release MISMATCH: got '$UNAME_R', port expects '$RELEASE'"
    info "continuing anyway - other sections are still collected"
fi
gp() {
    if command -v getprop >/dev/null 2>&1; then
        getprop "$1" 2>/dev/null
    else
        echo "(no getprop)"
    fi
}
lg "ro.product.device          : $(gp ro.product.device)"
lg "ro.product.model           : $(gp ro.product.model)"
lg "ro.product.brand           : $(gp ro.product.brand)"
lg "ro.build.fingerprint       : $(gp ro.build.fingerprint)"
lg "ro.build.version.incremental: $(gp ro.build.version.incremental)"
lg "ro.build.version.release   : $(gp ro.build.version.release)"
lg "ro.build.version.security_patch: $(gp ro.build.version.security_patch)"
lg "ro.boot.slot_suffix        : $(gp ro.boot.slot_suffix)"
lg "ro.hardware                : $(gp ro.hardware)"
kv "uname_release=$UNAME_R"
kv "fingerprint=$(gp ro.build.fingerprint)"

# ----------------------------------------------------------- S2 selinux
sec "S2 selinux"
if command -v getenforce >/dev/null 2>&1; then
    lg "getenforce : $(getenforce 2>/dev/null)"
else
    skip "getenforce not available"
fi

# ------------------------------------------------------- S3 cpu/mem/rlimits
sec "S3 cpus / memory / rlimits"
NCPU=0
if [ -d "$CPUDIR" ]; then
    NCPU=$(ls "$CPUDIR" 2>/dev/null | grep -c '^cpu[0-9][0-9]*$')
fi
lg "cpus present : $NCPU (engine pins CPU 2; needs >= 3)"
if [ "$NCPU" -ge 3 ]; then V_CPUS=1; ok "cpu count $NCPU >= 3"; else bad "cpu count $NCPU < 3"; fi
if [ -r "$MEMINFO" ]; then
    set -- $(grep '^MemTotal' "$MEMINFO" 2>/dev/null)
    [ -n "$2" ] && lg "MemTotal     : $2 $3"
    set -- $(grep '^MemAvailable' "$MEMINFO" 2>/dev/null)
    [ -n "$2" ] && lg "MemAvailable : $2 $3"
else
    skip "$MEMINFO unreadable"
fi
lg "max_map_count: $(cat /proc/sys/vm/max_map_count 2>/dev/null || echo unreadable) (engine maps 50000 VMAs)"
if [ -r "$LIMITS" ]; then
    grep -e 'open files' -e 'processes' -e 'pending signals' "$LIMITS" \
        > "$WORK/rlimits.txt" 2>/dev/null
    while IFS= read -r _l; do lg "limit: $_l"; done < "$WORK/rlimits.txt"
else
    skip "$LIMITS unreadable"
fi

# --------------------------------------------------- S4 tracefs access matrix
sec "S4 tracefs access matrix (engine runs as shell uid)"
if [ -d "$TR" ]; then
    ok "tracefs present at $TR"
else
    bad "tracefs NOT mounted at $TR (engine hardcodes this path)"
    if [ -d "$TRDBG" ]; then
        info "debugfs fallback exists at $TRDBG (port would need a TR override)"
    fi
fi
lg "events dir listing (kmem) :"
ls "$TR/events/kmem" > "$WORK/kmem_events.txt" 2>/dev/null \
    && lg "$(cat "$WORK/kmem_events.txt")" \
    || skip "cannot list $TR/events/kmem"
ls "$TR/events" > "$WORK/events_list.txt" 2>/dev/null \
    && info "$(wc -l < "$WORK/events_list.txt") event classes total (saved)"

for _ev in kmem_cache_alloc mm_page_alloc mm_page_free rss_stat; do
    if [ -d "$TR/events/kmem/$_ev" ]; then
        V_KMEM_EVENTS=$((V_KMEM_EVENTS + 1))
        ok "kmem event present: $_ev"
        _idf="$TR/events/kmem/$_ev/id"
        [ -r "$_idf" ] && info "  id file: $(cat "$_idf" 2>/dev/null)" \
            || info "  id file unreadable (expected on locked-down builds)"
        _fmtf="$TR/events/kmem/$_ev/format"
        if [ -r "$_fmtf" ]; then
            head -c 1024 "$_fmtf" > "$WORK/ev_format_${_ev}.txt" 2>/dev/null
            info "  format readable (saved)"
        else
            info "  format unreadable (engine parses raw records without it)"
        fi
    else
        bad "kmem event MISSING: $_ev"
    fi
done

# raw buffer read test (non-blocking via timeout; plain dd fallback)
_c2fail=0
for _c in 0 2; do
    _raw="$TR/per_cpu/cpu$_c/trace_pipe_raw"
    if [ -f "$_raw" ]; then
        if command -v timeout >/dev/null 2>&1; then
            if timeout 3 head -c 4096 "$_raw" > /dev/null 2>&1; then
                [ "$_c" = "0" ] && { V_RAW_READ=1; ok "trace_pipe_raw readable (cpu$_c)"; }
            else
                bad "trace_pipe_raw read failed (cpu$_c)"
                [ "$_c" = "2" ] && _c2fail=1
            fi
        else
            if dd if="$_raw" bs=64 count=1 > /dev/null 2>&1; then
                [ "$_c" = "0" ] && { V_RAW_READ=1; ok "trace_pipe_raw readable (cpu$_c, no timeout tool)"; }
            else
                bad "trace_pipe_raw read failed (cpu$_c)"
                [ "$_c" = "2" ] && _c2fail=1
            fi
        fi
    else
        bad "trace_pipe_raw MISSING (cpu$_c)"
    fi
done
if [ "$_c2fail" = "1" ]; then
    info "cpu2 raw-read note: a QUIET cpu starves the blocking read until"
    info "the timeout even when permissions are fine (observed 2026-11-12:"
    info "the same probe later pulled 1 MB from cpu2 in S9 with events"
    info "flowing). Treat this line as informational; it only matters if"
    info "the engine also fails to read cpu2 while its own events are on."
fi

# tracing_on write test (write the saved value back = no state change)
if [ -f "$TR/tracing_on" ]; then
    state_save "$TR/tracing_on"
    _cur="$(cat "$TR/tracing_on" 2>/dev/null)"
    if wr "$TR/tracing_on" "$_cur"; then
        V_TRON_WRITE=1; ok "tracing_on writable (value unchanged: '$_cur')"
    else
        bad "tracing_on NOT writable from this uid"
    fi
else
    bad "tracing_on MISSING"
fi

# kmem event enable write test (write current value back)
_EN_OK=0
for _ev in kmem_cache_alloc mm_page_alloc mm_page_free rss_stat; do
    _ef="$TR/events/kmem/$_ev/enable"
    [ -f "$_ef" ] || continue
    state_save "$_ef"
    _cur="$(cat "$_ef" 2>/dev/null)"
    case "$_cur" in
        0|1|X) _w="$_cur" ;;
        *)     _w="0" ;;
    esac
    if wr "$_ef" "$_w"; then
        _EN_OK=$((_EN_OK + 1))
    else
        info "enable file not writable: $_ev"
    fi
done
if [ "$_EN_OK" -ge 3 ]; then
    V_EV_WRITE=1
    ok "kmem event enable files writable ($_EN_OK/4)"
elif [ "$_EN_OK" -gt 0 ]; then
    info "only $_EN_OK/4 enable files writable"
else
    bad "no kmem enable file writable (direct event enable blocked)"
fi

# rss_stat trigger route (what the engine actually uses)
_TGF="$TR/events/kmem/rss_stat/trigger"
if [ -f "$_TGF" ]; then
    if wr "$_TGF" "enable_event:kmem:mm_page_alloc"; then
        sleep 1
        wr "$_TGF" "!enable_event:kmem:mm_page_alloc"
        if grep -q '^enable_event:kmem:mm_page_alloc' "$_TGF" 2>/dev/null; then
            bad "trigger write ok but removal left residue (manual check advised)"
            V_TRIG_WRITE=1
        else
            V_TRIG_WRITE=1
            ok "rss_stat trigger route works (added + removed cleanly)"
        fi
    else
        bad "rss_stat trigger file NOT writable"
    fi
else
    skip "rss_stat trigger file missing"
fi

# instances/ mkdir test
_IN="$TR/instances/x6873probe"
if [ -d "$TR/instances" ]; then
    if mkdir "$_IN" 2>/dev/null; then
        if wr "$_IN/buffer_size_kb" "4"; then
            V_INST=1
            ok "instances/ creatable + writable (rd_setup requirement)"
        else
            info "instance created but buffer_size_kb not writable"
        fi
        # on a plain directory the write test above leaves a regular file
        # behind; on tracefs the rm fails harmlessly (files are kernel-owned)
        rm -f "$_IN/buffer_size_kb" 2>/dev/null
        rmdir "$_IN" 2>/dev/null \
            || info "WARNING: could not remove $_IN (harmless empty instance; remove manually)"
    else
        bad "cannot create instance under $TR/instances"
    fi
else
    bad "instances/ dir MISSING (engine rd_setup needs it)"
fi

# kprobe_events test (register + immediately unregister, never enabled)
if [ -f "$TR/kprobe_events" ]; then
    if wr "$TR/kprobe_events" "p:x6873pb_capable capable"; then
        wr "$TR/kprobe_events" "-:x6873pb_capable"
        if grep -q '^p:x6873pb_capable' "$TR/kprobe_events" 2>/dev/null; then
            bad "kprobe registered but NOT removed (cleanup failed)"
            V_KPROBE=1
        else
            V_KPROBE=1
            ok "kprobe_events usable (registered + removed cleanly)"
        fi
    else
        bad "kprobe_events NOT writable (CONFIG_KPROBE_EVENTS off or blocked)"
    fi
else
    bad "kprobe_events MISSING"
fi

# --------------------------------------------------------- S5 sysctls
sec "S5 sysctls"
for _s in kernel/kptr_restrict kernel/dmesg_restrict \
          kernel/perf_event_paranoid kernel/unprivileged_bpf_disabled \
          kernel/yama/ptrace_scope vm/mmap_min_addr; do
    _v="$(cat "/proc/sys/$_s" 2>/dev/null)" \
        && lg "$_s = $_v" \
        || lg "$_s = (absent/unreadable)"
done
cp "/proc/sys/kernel/kptr_restrict" "$WORK/" 2>/dev/null

# dmesg boot header (dmesg_restrict=0 on this build): the arm64
# "Virtual kernel memory layout" lines pin the runtime kimage/direct-map
# ranges, which the offline analysis needs to convert observed runtime
# call sites into linked-image offsets when kallsyms is zeroed (exactly
# the 2026-11-12 situation). Long-uptime devices may have rotated the
# boot lines out of the ring - save whatever is there.
if command -v dmesg >/dev/null 2>&1; then
    if dmesg 2>/dev/null | head -n 400 > "$WORK/dmesg_head.txt" && \
       [ -s "$WORK/dmesg_head.txt" ]; then
        grep -i -m 40 -e "virtual kernel memory" -e "memory layout" \
            -e "kimage" -e "Booting Linux on physical CPU" \
            "$WORK/dmesg_head.txt" > "$WORK/dmesg_layout.txt" 2>/dev/null
        ok "dmesg boot head saved ($(wc -l < "$WORK/dmesg_head.txt") lines; \
layout hits: $(wc -l < "$WORK/dmesg_layout.txt" 2>/dev/null || echo 0))"
    else
        skip "dmesg empty or unreadable (restricted?)"
    fi
else
    skip "dmesg tool not available"
fi

# ------------------------------------------------- S6 kallsyms visibility
sec "S6 kallsyms visibility (symbols the port needs)"
SYMS="panic_on_warn root_user init_user_ns init_ucounts init_groups \
init_task init_cred root_task_group selinux_state do_timer_create \
copy_process dup_task_struct kmem_cache_alloc kmem_cache_alloc_noprof \
__tracepoint_sys_exit"
if [ -r "$KS" ]; then
    ok "kallsyms readable at $KS"
    _vis=0; _tot=0
    : > "$WORK/kallsyms.selected.txt"
    for _s in $SYMS; do
        _m="$(grep " $_s\$" "$KS" 2>/dev/null | head -n 2)"
        if [ -n "$_m" ]; then
            printf '%s\n' "$_m" >> "$WORK/kallsyms.selected.txt"
            set -- $_m
            _tot=$((_tot + 1))
            if [ "$1" != "0000000000000000" ]; then
                _vis=$((_vis + 1))
                lg "  $_s : $1 $2"
            else
                lg "  $_s : ADDRESS HIDDEN (zeroed)"
            fi
        else
            lg "  $_s : not in kallsyms"
        fi
    done
    lg "visible: $_vis/$_tot matched symbols have real addresses"
    if [ "$_tot" -gt 0 ] && [ "$_vis" -ge "$_tot" ]; then
        V_KSYM_VISIBLE=1
        ok "kallsyms fully visible - symbols derivable WITHOUT root"
    elif [ "$_vis" -gt 0 ]; then
        info "kallsyms PARTIALLY visible ($_vis/$_tot) - record values, root will confirm"
    else
        bad "kallsyms addresses hidden (kptr_restrict) - symbol derivation needs root"
    fi
else
    skip "kallsyms unreadable at $KS"
fi

# ----------------------------------------------------------- S7 slabinfo
sec "S7 slabinfo"
if [ -r "$SLABINFO" ]; then
    V_SLAB=1
    cp "$SLABINFO" "$WORK/slabinfo.txt" 2>/dev/null
    ok "slabinfo readable (full copy saved)"
    lg "rows of interest:"
    grep -i -e task_struct -e cred -e k_itimer -e timer -e signal \
        -e mm_struct -e sighand -e files_cache "$SLABINFO" 2>/dev/null \
        | head -24 > "$WORK/slab_rows.txt"
    while IFS= read -r _l; do lg "  $_l"; done < "$WORK/slab_rows.txt"
else
    bad "slabinfo unreadable from this uid (root copy attempted in S10)"
fi

# ------------------------------------------------------------- S8 config
sec "S8 kernel config (IKCONFIG)"
if [ -r "$CONFIGGZ" ]; then
    if gzip -dc "$CONFIGGZ" > "$WORK/kernel.config" 2>/dev/null; then
        V_CONFIG=1
        ok "config extracted (full copy saved)"
        grep -e 'CONFIG_POSIX_TIMERS' -e 'CONFIG_TRACING' \
             -e 'CONFIG_KPROBE_EVENTS' -e 'CONFIG_KPROBES' \
             -e 'CONFIG_SLUB' -e 'CONFIG_SLAB' \
             -e 'CONFIG_RANDOM_KMALLOC_CACHES' \
             -e 'CONFIG_INIT_ON_ALLOC' -e 'CONFIG_INIT_ON_FREE' \
             -e 'CONFIG_KASAN' -e 'CONFIG_PREEMPT' \
             -e 'CONFIG_KALLSYMS' -e 'CONFIG_HARDENED_USERCOPY' \
             -e 'CONFIG_SECURITY_SELINUX' -e 'CONFIG_IKCONFIG' \
             "$WORK/kernel.config" 2>/dev/null > "$WORK/config_keys.txt"
        while IFS= read -r _l; do lg "  $_l"; done < "$WORK/config_keys.txt"
    else
        bad "config.gz readable but gunzip failed"
    fi
else
    skip "config.gz unreadable at $CONFIGGZ"
fi

# ------------------------------------- S9 one-shot kmem capture (restored)
sec "S9 one-shot kmem trace capture (fork churn only, state restored)"
if [ "$V_TRON_WRITE" = "1" ] && [ "$V_KMEM_EVENTS" -ge 3 ] && \
   { [ "$V_EV_WRITE" = "1" ] || [ "$V_TRIG_WRITE" = "1" ]; }; then
    # save everything we will touch
    state_save "$TR/tracing_on"
    state_save "$TR/buffer_size_kb"
    for _ev in kmem_cache_alloc mm_page_alloc mm_page_free rss_stat; do
        state_save "$TR/events/kmem/$_ev/enable"
    done
    # fatten the buffer first (resize clears it; do it before enabling)
    if wr "$TR/buffer_size_kb" "1024"; then
        info "buffer resized to 1024 KB/cpu"
    elif wr "$TR/buffer_size_kb" "256"; then
        info "buffer resized to 256 KB/cpu"
    else
        info "buffer resize unavailable - capturing with the default size"
    fi
    # enable the three kmem events - direct first, trigger route as fallback
    _ROUTE=""
    if [ "$V_EV_WRITE" = "1" ]; then
        _n=0
        wr "$TR/events/kmem/kmem_cache_alloc/enable" "1" && _n=$((_n + 1))
        wr "$TR/events/kmem/mm_page_alloc/enable" "1" && _n=$((_n + 1))
        wr "$TR/events/kmem/mm_page_free/enable" "1" && _n=$((_n + 1))
        [ "$_n" -eq 3 ] && _ROUTE="direct"
    fi
    if [ -z "$_ROUTE" ] && [ "$V_TRIG_WRITE" = "1" ]; then
        _n=0
        wr "$TR/events/kmem/rss_stat/enable" "1" && _n=$((_n + 1))
        wr "$TR/events/kmem/rss_stat/trigger" "enable_event:kmem:kmem_cache_alloc" && _n=$((_n + 1))
        wr "$TR/events/kmem/rss_stat/trigger" "enable_event:kmem:mm_page_alloc" && _n=$((_n + 1))
        wr "$TR/events/kmem/rss_stat/trigger" "enable_event:kmem:mm_page_free" && _n=$((_n + 1))
        [ "$_n" -eq 4 ] && _ROUTE="rss_stat-trigger"
    fi
    if [ -n "$_ROUTE" ]; then
        lg "capture route: $_ROUTE"
        wr "$TR/tracing_on" "1"
        # churn: sequential + parallel forks generate dup_task_struct /
        # kmem_cache_alloc / mm_page_* records with this shell's pids
        _i=0
        while [ "$_i" -lt 40 ]; do
            ( ls /system/app > /dev/null 2>&1 )
            _i=$((_i + 1))
        done
        _i=0
        while [ "$_i" -lt 16 ]; do
            ( ls /system/etc > /dev/null 2>&1 ) &
            _i=$((_i + 1))
        done
        wait
        wr "$TR/tracing_on" "0"
        # capture raw + text from the first three cpus
        for _c in 0 1 2; do
            _raw="$TR/per_cpu/cpu$_c/trace_pipe_raw"
            [ -f "$_raw" ] || continue
            if command -v timeout >/dev/null 2>&1; then
                timeout 5 head -c 2097152 "$_raw" > "$WORK/cap_cpu$_c.raw" 2>/dev/null
            else
                dd if="$_raw" of="$WORK/cap_cpu$_c.raw" bs=4096 count=512 2>/dev/null
            fi
            _txt="$TR/per_cpu/cpu$_c/trace"
            [ -f "$_txt" ] && \
                head -c 262144 "$_txt" > "$WORK/cap_cpu$_c.txt" 2>/dev/null
        done
        _sz=0
        for _c in 0 1 2; do
            [ -f "$WORK/cap_cpu$_c.raw" ] && \
                _sz=$((_sz + $(wc -c < "$WORK/cap_cpu$_c.raw")))
        done
        if [ "$_sz" -gt 0 ]; then
            ok "captured $_sz byte(s) of raw kmem records (3 cpus, saved)"
            info "offline analysis: call-site histogram recovers the"
            info "dup_task_struct site; the timer site needs the derive"
            info "script's prober or the dumped boot image"
        else
            bad "capture produced 0 bytes (events enabled but no records?)"
        fi
        # disable / remove what we enabled, then restore saved state
        if [ "$_ROUTE" = "direct" ]; then
            wr "$TR/events/kmem/kmem_cache_alloc/enable" "0"
            wr "$TR/events/kmem/mm_page_alloc/enable" "0"
            wr "$TR/events/kmem/mm_page_free/enable" "0"
        else
            wr "$TR/events/kmem/rss_stat/trigger" "!enable_event:kmem:kmem_cache_alloc"
            wr "$TR/events/kmem/rss_stat/trigger" "!enable_event:kmem:mm_page_alloc"
            wr "$TR/events/kmem/rss_stat/trigger" "!enable_event:kmem:mm_page_free"
            wr "$TR/events/kmem/rss_stat/enable" "0"
        fi
        state_restore
        ok "capture done; tracefs restored"
    else
        bad "could not enable kmem events by any route - capture skipped"
        state_restore
    fi
else
    skip "S9 capture skipped (S4 write matrix not satisfied)"
fi

# -------------------------------------------------- S10 root / managers
sec "S10 root availability & managers"
if command -v su >/dev/null 2>&1; then
    _suout=""
    if command -v timeout >/dev/null 2>&1; then
        _suout="$(timeout 8 su -c id 2>/dev/null)"
    else
        _suout="$(su -c id 2>/dev/null)"
    fi
    case "$_suout" in
        *uid=0*)
            V_ROOT=1; V_ROOT_UNKNOWN=0
            ok "su grants root ($_suout)"
            su -c 'ls /data/adb' > "$WORK/data_adb.txt" 2>/dev/null \
                && { lg "/data/adb : $(tr '\n' ' ' < "$WORK/data_adb.txt")"; } \
                || info "/data/adb not listable via su"
            if [ "$V_KSYM_VISIBLE" != "1" ]; then
                if su -c "cat $KS" > "$WORK/kallsyms.root.txt" 2>/dev/null; then
                    _vis=0; _tot=0
                    for _s in $SYMS; do
                        _m="$(grep " $_s\$" "$WORK/kallsyms.root.txt" 2>/dev/null | head -1)"
                        if [ -n "$_m" ]; then
                            set -- $_m
                            _tot=$((_tot + 1))
                            [ "$1" != "0000000000000000" ] && _vis=$((_vis + 1))
                            lg "  (root) $_s : $1 $2"
                        fi
                    done
                    lg "root kallsyms: $_vis/$_tot symbols visible (full copy saved)"
                else
                    info "root kallsyms copy failed"
                fi
            fi
            if [ "$V_SLAB" != "1" ]; then
                su -c "cat $SLABINFO" > "$WORK/slabinfo.root.txt" 2>/dev/null \
                    && info "root slabinfo copy saved"
            fi
            ;;
        *)
            info "su exists but denied root for this uid ('$_suout')"
            ;;
    esac
else
    info "no su binary in PATH (root sections skipped)"
fi
if command -v pm >/dev/null 2>&1; then
    pm list packages 2>/dev/null \
        | grep -i -e ghost -e ksu -e sukisu -e finasu -e apatch \
                  -e magisk -e shizuku -e kernel \
        > "$WORK/packages.txt"
    _pn=$(wc -l < "$WORK/packages.txt" 2>/dev/null || echo 0)
    lg "interesting packages ($_pn) :"
    while IFS= read -r _l; do lg "  $_l"; done < "$WORK/packages.txt" 2>/dev/null
else
    skip "pm not available (not running under adb/app shell?)"
fi
kv "root_available=$V_ROOT"

# ------------------------------------------------------- S11 boot partitions
sec "S11 boot partitions"
if [ -d "$BYNAME" ]; then
    ls -l "$BYNAME" 2>/dev/null | grep -i -e boot -e vbmeta \
        > "$WORK/byname_boot.txt"
    while IFS= read -r _l; do lg "  $_l"; done < "$WORK/byname_boot.txt"
    _slot="$(gp ro.boot.slot_suffix)"
    kv "boot_slot=$_slot"
    if [ "$DUMP_BOOT" = "1" ]; then
        if [ "$V_ROOT" = "1" ]; then
            _dev="$BYNAME/boot$_slot"
            if [ -b "$_dev" ] || [ -f "$_dev" ]; then
                _out="$WORK/boot$_slot.img"
                lg "dumping $_dev to bundle (this takes a while)..."
                if su -c "dd if=$_dev of=$_out bs=1048576" > /dev/null 2>&1; then
                    su -c "chmod 644 $_out" > /dev/null 2>&1
                    lg "  sha256: $(sha256sum "$_out" 2>/dev/null)"
                    lg "  size  : $(wc -c < "$_out" 2>/dev/null) byte(s)"
                    ok "boot image dumped (for offline recover.py constants)"
                else
                    bad "dd of $_dev failed"
                fi
            else
                bad "boot device not found at $_dev"
            fi
        else
            skip "--dump-boot needs root (su denied or absent)"
        fi
    else
        info "--dump-boot not requested (add it to also copy the boot image)"
    fi
else
    skip "$BYNAME not listable"
fi

# ---------------------------------------------------------- S12 summary
sec "S12 verdict summary"
lg "checks: ok=$N_OK fail=$N_FAIL skip=$N_SKIP"
kv "release_match=$V_RELEASE"
kv "tracefs_raw_read=$V_RAW_READ"
kv "tracing_on_write=$V_TRON_WRITE"
kv "kmem_event_enable_write=$V_EV_WRITE"
kv "rss_stat_trigger_write=$V_TRIG_WRITE"
kv "instances_write=$V_INST"
kv "kprobe_events=$V_KPROBE"
kv "kmem_events_present=$V_KMEM_EVENTS/4"
kv "cpus_ge_3=$V_CPUS"
kv "kallsyms_visible=$V_KSYM_VISIBLE"
kv "slabinfo=$V_SLAB"
kv "config=$V_CONFIG"
kv "root=$V_ROOT"

ENGINE=0
if [ "$V_RELEASE" = "1" ] && [ "$V_RAW_READ" = "1" ] && \
   [ "$V_TRON_WRITE" = "1" ] && [ "$V_KMEM_EVENTS" -ge 3 ] && \
   { [ "$V_EV_WRITE" = "1" ] || [ "$V_TRIG_WRITE" = "1" ]; } && \
   [ "$V_CPUS" = "1" ]; then
    ENGINE=1
fi
kv "engine_runnable_as_shell=$ENGINE"
if [ "$ENGINE" = "1" ]; then
    if [ "$V_ROOT_RUN" = "1" ]; then
        lg "VERDICT engine: RUNNABLE - but measured as ROOT in this run."
        lg "                 Re-run WITHOUT su to prove the unprivileged"
        lg "                 shell-uid path the real engine uses."
    else
        lg "VERDICT engine: the Shark engine can run from this shell uid"
    fi
    if [ "$V_KSYM_VISIBLE" = "1" ]; then
        lg "VERDICT derive : PATH A - full constants derivation WITHOUT root"
        lg "                 (kallsyms visible + tracefs writable). Run"
        lg "                 ports/x6873/tools/derive-consts.sh WITHOUT su."
    elif [ "$V_ROOT" = "1" ]; then
        lg "VERDICT derive : PATH B - derivation with temporary root"
        lg "                 (kallsyms hidden but su works). Run"
        lg "                 ports/x6873/tools/derive-consts.sh under su -"
        lg "                 it lifts kptr_restrict=2 by itself (this build"
        lg "                 zeroes kallsyms even for root, observed in the"
        lg "                 2026-11-12 bundle: root kallsyms 0/14 visible)."
    else
        lg "VERDICT derive : PATH B-nosu - kallsyms hidden and no su here."
        lg "                 Root the device once (GhostLock), or re-run with"
        lg "                 --dump-boot from a rooted shell for offline work."
    fi
else
    lg "VERDICT engine: BLOCKED from this uid - failed requirement(s):"
    [ "$V_RELEASE" = "1" ]      || lg "  - release gating mismatch"
    [ "$V_RAW_READ" = "1" ]     || lg "  - trace_pipe_raw not readable"
    [ "$V_TRON_WRITE" = "1" ]   || lg "  - tracing_on not writable"
    [ "$V_KMEM_EVENTS" -ge 3 ]  || lg "  - kmem tracepoints missing"
    { [ "$V_EV_WRITE" = "1" ] || [ "$V_TRIG_WRITE" = "1" ]; } || \
        lg "  - no kmem enable route (direct or trigger)"
    [ "$V_CPUS" = "1" ]         || lg "  - fewer than 3 cpus"
    lg "  Report these lines back; the port needs a different launch path."
fi
lg ""
lg "NEXT: send back the full console output AND the bundle"
lg "      ${WORK}.tar.gz (created on exit)"

# ------------------------------------------------------------- exit path
on_exit() {
    _rc=$?
    state_restore
    _dir="$(dirname "$WORK")"
    _base="$(basename "$WORK")"
    _bs=""
    if ( cd "$_dir" 2>/dev/null && tar -czf "${_base}.tar.gz" "$_base" ) \
        2>/dev/null; then
        _b="$_dir/${_base}.tar.gz"
        _bs="$(du -h "$_b" 2>/dev/null | cut -f1)"
    elif ( cd "$_dir" 2>/dev/null && tar -cf "${_base}.tar" "$_base" && \
           gzip -9 "${_base}.tar" ) 2>/dev/null; then
        _b="$_dir/${_base}.tar.gz"
        _bs="$(du -h "$_b" 2>/dev/null | cut -f1)"
    else
        _b="(bundle failed - send the directory $_dir/$_base instead)"
    fi
    printf '%s\n' "[done] rc=$_rc bundle=$_b"
    [ -n "$_bs" ] && printf '%s\n' "[done] bundle size: $_bs"
}
trap on_exit 0
trap 'exit 130' INT
trap 'exit 143' TERM
exit 0
