#!/usr/bin/env python3
"""parse_x6873_stock.py v2 — Task 15 (ref #14): parse the X6873 stock kernel
Image (6.1.157) with the Shark-Releases add-device mechanism
(kallsyms by-structure + BL-scan + BTF) and diff against the device-measured
baseline (Task 8) and/or a second firmware version.

v2 — anchored discovery (supersedes the recover.py load_syms path, which
fails on this build because):
  * kallsyms_relative_base = 0xffffffc008000000 (NOT the 0xffffffc080000000
    needle recover.py searches for), and
  * the linker placed ~300 KB of other .rodata between kallsyms_names and
    kallsyms_markers/token_table, so the markers walk-back breaks.

Algorithm:
  1. scan for a long strictly-nondecreasing s32 run (>= 40000 entries,
     first = 0, last in [0x1000000, 0x4000000]) -> kallsyms_offsets
  2. read kallsyms_relative_base (u64, 0xffffff........) + kallsyms_num_syms
     (u64 == n) right after the array (8-aligned, small padding window)
  3. decode the compressed names blob right after num_syms using the token
     table located by recover.py's token_index()
  4. verify: first records are T_text / T_stext, count == n
  5. BL-scan: full call map of do_timer_create / copy_process /
     dup_task_struct (every bl resolved to its target symbol)
  6. BTF structs via recover.py's btf()

Usage:
  parse <kernel_image> <out_json>
  diff  <json_v150> <json_v160>     two parse outputs -> verdict table + JSON
"""
import bisect
import importlib.util
import json
import re
import struct
import sys

import os
RECOVER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      os.pardir, os.pardir, 'v2505a', 'recover.py')
DIFF_OUT = None  # third positional arg of diff mode, or stdout

# Device-measured baseline (kallsyms ter-lift, XOS 16.3.x aktif, non-reboot)
BASELINE = {
    'release_banner_suffix': 'ab15601211',
    'do_timer_create': 0x193258,
    'copy_site_dup_task_struct+0x54': 0xac148,
    'selinux_state': 0x225b820,
    'panic_on_warn': 0x200ae0c,
    'root_user': 0x2030780,
    'init_user_ns': 0x20304f0,
    'init_ucounts': 0x2032008,
    'init_groups': 0x2031aa0,
    'init_task': 0x201f640,
    'init_cred': 0x2031aa8,
    'root_task_group': 0x2209980,
    'timer_site_prediction': 0x193300,   # do_timer_create+0xa8, jendela +0x94..0xb8
}

SYMBOL_TARGETS = [
    'do_timer_create', 'copy_process', 'dup_task_struct', '__tracepoint_sys_exit',
    'selinux_state', 'panic_on_warn', 'root_user', 'init_user_ns',
    'init_ucounts', 'init_groups', 'init_task', 'init_cred', 'root_task_group',
    'kmem_cache_alloc', 'kmem_cache_alloc_trace', 'kmem_cache_alloc_node',
]


def load_recover():
    spec = importlib.util.spec_from_file_location('recover', RECOVER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def banner(d: bytes):
    m = re.search(rb'Linux version [ -~]{10,200}', d)
    return m.group(0).decode() if m else None


def find_offsets_runs(d):
    """Long monotonic s32 runs (candidate kallsyms_offsets arrays)."""
    N = len(d)
    runs = []
    i = 0
    while i < N - 4:
        if struct.unpack_from('<i', d, i)[0] != 0:
            i += 4
            continue
        j = i + 4
        prev = 0
        while j < N - 4:
            v = struct.unpack_from('<i', d, j)[0]
            if v < prev or v > 0x4000000:
                break
            prev = v
            j += 4
        n = (j - i) // 4
        if n >= 40000 and 0x1000000 <= prev <= 0x4000000:
            runs.append((i, n, prev))
        i = j if j > i + 4 else i + 4
    return runs


def decode_names(d, toks, start, count):
    syms, p = [], start
    for _ in range(count):
        if p >= len(d):
            return None, p
        l = d[p]
        p += 1
        if l & 0x80:
            if p >= len(d):
                return None, p
            l = ((l & 0x7f) | (d[p] << 7))
            p += 1
        if not l or l > 400 or p + l > len(d):
            return None, p
        o = bytearray()
        for b in d[p:p + l]:
            o += toks[b]
        syms.append(bytes(o))
        p += l
    return syms, p


class Kallsyms:
    """kallsyms view + recover.py reuse (bl-scan / BTF)."""

    def __init__(self, d, rel_base, offs, syms, rec):
        self.d = d
        self.base = rel_base
        self.offs = offs
        self.sym = [s[1:].decode('latin1') for s in syms]
        self.typ = [s[:1].decode('latin1') for s in syms]
        self.n = len(self.sym)
        self._rec = rec          # recover.py module (bl_from/btf reuse)
        self._sorted_offs = None

    def addr(self, name):
        try:
            i = self.sym.index(name)
        except ValueError:
            return None
        return self.base + self.offs[i]

    def resolve(self, va):
        """nearest symbol at/below va (for call-map resolution)."""
        if self._sorted_offs is None:
            self._sorted_offs = self.offs
        off = va - self.base
        i = bisect.bisect_right(self.offs, off) - 1
        if i < 0:
            return None
        return self.sym[i], off - self.offs[i]

    def call_map(self, func, max_len=0x8000):
        """every bl instruction in func -> (bl_va, site, target_symbol, delta)."""
        i = self.sym.index(func)
        st = self.addr(func)
        nxt = self.base + self.offs[i + 1] if i + 1 < self.n else st + max_len
        en = min(nxt, st + max_len)
        out = []
        va = st
        while va < en:
            x = struct.unpack_from('<I', self.d, va - self.base)[0]
            if (x & 0xFC000000) == 0x94000000:
                imm = x & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                tgt = va + imm * 4
                r = self.resolve(tgt)
                out.append({'bl': va - self.base, 'site': va - self.base + 4,
                            'target': r[0] if r else f'{tgt:#x}',
                            'func_delta': va - st})
            va += 4
        return out


def parse(path, out_json):
    d = open(path, 'rb').read()
    rec = load_recover()

    # token table first (recover.py's structural scan, verified below)
    probe = rec.Image(path)
    S, TT, idx = probe.token_index()
    toks = [d[S + idx[i]:d.find(b'\x00', S + idx[i])] for i in range(256)]

    ks = None
    for (st, n, last) in find_offsets_runs(d):
        end = st + 4 * n
        for rb_off in range(end, end + 0x24, 4):
            rb = struct.unpack_from('<Q', d, rb_off)[0] if rb_off + 8 <= len(d) else 0
            if not (0xffffff8000000000 <= rb <= 0xfffffffffff00000):
                continue
            # num_syms shortly after relative_base
            for ns_off in range(rb_off + 8, rb_off + 8 + 0x20, 4):
                num = struct.unpack_from('<Q', d, ns_off)[0]
                if num != n:
                    continue
                for names_st in (ns_off + 8, ns_off + 12):
                    syms, names_end = decode_names(d, toks, names_st, n)
                    if syms is None or len(syms) != n:
                        continue
                    if not (syms[0].startswith(b'T') or syms[0].startswith(b't')):
                        continue
                    if b'_text' not in syms[0] and b'_stext' not in syms[0]:
                        continue
                    if not syms[-1].endswith(b'_end'):
                        continue
                    offs = struct.unpack_from(f'<{n}i', d, st)
                    ks = (Kallsyms(d, rb, offs, syms, rec), {
                        'offsets_at': st, 'num_syms': n, 'relative_base': rb,
                        'names_start': names_st, 'names_end': names_end,
                        'token_table_at': S, 'token_index_at': TT,
                    })
                    break
                if ks:
                    break
            if ks:
                break
        if ks:
            break
    if ks is None:
        raise SystemExit('kallsyms not located (anchored discovery failed)')

    k, meta = ks
    syms = {w: k.addr(w) for w in SYMBOL_TARGETS}
    km = k.addr('kmem_cache_alloc')
    kmn = k.addr('kmem_cache_alloc_node')

    callmaps = {}
    for fn in ('do_timer_create', 'copy_process', 'dup_task_struct'):
        if k.addr(fn):
            callmaps[fn] = k.call_map(fn)

    # recover.py BTF (shim: reuse its btf() bound to a probe with our data)
    probe.d = d
    btf_raw = probe.btf()
    btf = {}
    for s in ('k_itimer', 'cred', 'task_struct', 'selinux_state',
              'task_security_struct', 'tracepoint'):
        if s in btf_raw:
            size, mem = btf_raw[s]
            btf[s] = {'size': size, 'members': mem}

    res = {
        'image': path,
        'banner': banner(d),
        'release_match_baseline': (banner(d) or '').find(
            BASELINE['release_banner_suffix']) >= 0,
        'kallsyms_meta': meta,
        'syms_va': {kk: v for kk, v in syms.items()},
        'syms_off': {kk: (v - k.base) for kk, v in syms.items() if v},
        'call_maps': callmaps,
        'btf': btf,
    }
    with open(out_json, 'w') as f:
        json.dump(res, f, indent=1)

    print(f"banner: {res['banner']}")
    print(f"release_match_baseline: {res['release_match_baseline']}")
    print(f"kallsyms: n={meta['num_syms']:,} relative_base={meta['relative_base']:#x} "
          f"offsets@{meta['offsets_at']:#x} names@{meta['names_start']:#x}..{meta['names_end']:#x}")
    for kk, v in res['syms_off'].items():
        print(f"  {kk:32s} off={v:#x}"
              + ("  BASELINE_MATCH" if BASELINE.get(kk) == v else ""))
    for fn, cms in callmaps.items():
        print(f"  call map {fn}:")
        for c in cms:
            print(f"    bl {c['bl']:#x} -> {c['target']:32s} (func+{c['func_delta']:#x}) "
                  f"site={c['site']:#x}")
    for s, info in btf.items():
        keys = [kk for kk in ('it', 'uid', 'cred', 'enforcing', 'exec_sid') if kk in info['members']]
        print(f"  BTF {s:22s} size={info['size']:#x} "
              f"{ {kk: hex(info['members'][kk]) for kk in keys} }")
    return res


def diff(j1path, j2path, out_path=None):
    j1 = json.load(open(j1path))
    j2 = json.load(open(j2path))
    keys = ['do_timer_create', 'copy_process', 'dup_task_struct',
            '__tracepoint_sys_exit', 'selinux_state', 'panic_on_warn',
            'root_user', 'init_user_ns', 'init_ucounts', 'init_groups',
            'init_task', 'init_cred', 'root_task_group']
    rows = []
    for kk in keys:
        o1 = j1['syms_off'].get(kk)
        o2 = j2['syms_off'].get(kk)
        rows.append({'const': kk, 'v150': o1, 'v160': o2,
                     'baseline': BASELINE.get(kk),
                     'match_150_base': BASELINE.get(kk) == o1 if o1 else None,
                     'match_160_base': BASELINE.get(kk) == o2 if o2 else None,
                     'same_across_versions': o1 == o2 if (o1 and o2) else None})
    # copy site: dup_task_struct + 0x54 (BL site = bl+4)
    d1 = j1['syms_off'].get('dup_task_struct')
    d2 = j2['syms_off'].get('dup_task_struct')
    rows.append({'const': 'copy_site dup_task_struct+0x54',
                 'v150': d1 + 0x54 if d1 else None,
                 'v160': d2 + 0x54 if d2 else None,
                 'baseline': BASELINE['copy_site_dup_task_struct+0x54'],
                 'match_150_base': d1 + 0x54 == BASELINE['copy_site_dup_task_struct+0x54'] if d1 else None,
                 'match_160_base': d2 + 0x54 == BASELINE['copy_site_dup_task_struct+0x54'] if d2 else None,
                 'same_across_versions': d1 == d2 if (d1 and d2) else None})
    # timer site: BL call to kmem_cache_alloc* inside do_timer_create
    def timer_sites(j):
        out = []
        for c in j.get('call_maps', {}).get('do_timer_create', []):
            if isinstance(c['target'], str) and c['target'].startswith('kmem_cache_alloc'):
                out.append(c['site'])
        return sorted(set(out))
    t1, t2 = timer_sites(j1), timer_sites(j2)
    rows.append({'const': 'timer_site (bl kmem_cache_alloc* in do_timer_create)',
                 'v150': t1, 'v160': t2,
                 'baseline': BASELINE['timer_site_prediction'],
                 'match_150_base': BASELINE['timer_site_prediction'] in t1 if t1 else None,
                 'match_160_base': BASELINE['timer_site_prediction'] in t2 if t2 else None,
                 'same_across_versions': t1 == t2 if (t1 and t2) else None})
    out = {'banners': {'v150': j1.get('banner'), 'v160': j2.get('banner')},
           'release_match': {'v150': j1.get('release_match_baseline'),
                             'v160': j2.get('release_match_baseline')},
           'kallsyms_meta': {'v150': j1.get('kallsyms_meta'),
                             'v160': j2.get('kallsyms_meta')},
           'rows': rows}
    if out_path:
        with open(out_path, 'w') as f:
            json.dump(out, f, indent=1)
    else:
        print(json.dumps(out, indent=1))

    def fmt(x):
        if isinstance(x, list):
            return '[' + ', '.join(f'{i:#x}' if isinstance(i, int) else str(i) for i in x) + ']'
        return f'{x:#x}' if isinstance(x, int) else str(x)

    hdr = f"{'constant':44s} {'150SP09':>14s} {'160SP02':>14s} {'baseline':>10s}  verdict"
    print(hdr)
    print('-' * len(hdr))
    for r in rows:
        f1, f2, fb = fmt(r['v150']), fmt(r['v160']), fmt(r['baseline'])
        v = []
        if r['same_across_versions'] is True:
            v.append('STABLE across versions')
        if r['same_across_versions'] is False:
            v.append('DIFFERS across versions')
        if r.get('match_150_base'):
            v.append('150=baseline')
        if r.get('match_160_base'):
            v.append('160=baseline')
        print(f"{r['const']:44s} {f1:>12s} {f2:>12s} {fb:>10s}  {', '.join(v) or '?'}")
    return out


if __name__ == '__main__':
    if len(sys.argv) >= 4 and sys.argv[1] == 'parse':
        sys.exit(0 if parse(sys.argv[2], sys.argv[3]) else 1)
    elif len(sys.argv) >= 4 and sys.argv[1] == 'diff':
        diff(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    else:
        print(__doc__)
