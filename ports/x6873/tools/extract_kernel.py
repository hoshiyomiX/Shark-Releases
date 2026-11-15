#!/usr/bin/env python3
"""extract_kernel.py — Task 15 (ref #14): extract the bare arm64 kernel Image
from an X6873 stock boot.img (Android boot image v0-v4, optional MTK pre-header,
kernel possibly gzip/lz4/zstd-compressed or raw).

Usage: extract_kernel.py <boot.img> <out_image.bin>

Emits diagnostics to stderr; exits 0 only when a valid arm64 Image
(magic ARMd @ +0x38) is written to out_image.bin.
"""
import gzip
import io
import os
import struct
import sys


def is_arm64_image(d: bytes) -> bool:
    return len(d) > 0x38 and d[0x38:0x3c] == b'ARMd'


def lz4_legacy_decompress(blob: bytes):
    """Android lz4-legacy: magic 0x184C2102 + [u32le size][lz4 block]* ; 0 = EOF.
    Each block expands to <= 8 MiB (LEGACY_BLOCK_SIZE)."""
    import lz4.block
    pos = 4
    out = bytearray()
    nblk = 0
    while pos + 4 <= len(blob):
        bsize = struct.unpack_from('<I', blob, pos)[0]
        pos += 4
        if bsize == 0:
            break                       # EOF marker
        if pos + bsize > len(blob):
            break                       # truncated tail
        out += lz4.block.decompress(bytes(blob[pos:pos + bsize]),
                                    uncompressed_size=8 * 1024 * 1024)
        pos += bsize
        nblk += 1
    if not out:
        return None
    return bytes(out), nblk


def find_android_header(d: bytes):
    for off in (0, 0x200, 0x1000):          # plain, MTK 512B pre-header, other
        if d[off:off + 8] == b'ANDROID!':
            return off
    return -1


def parse_v0(ho, d):
    kernel_size = struct.unpack_from('<I', d, ho + 8)[0]
    page_size = struct.unpack_from('<I', d, ho + 36)[0] or 4096
    hdr_ver = struct.unpack_from('<I', d, ho + 40)[0]
    return kernel_size, page_size, hdr_ver


def try_decompress(blob: bytes):
    """Return (image_bytes, method) or (None, None)."""
    if blob[:2] == b'\x1f\x8b':                      # gzip
        return gzip.decompress(blob), 'gzip'
    if blob[:4] == b'\x04\x22\x4d\x18':              # lz4 frame
        try:
            import lz4.frame
            return lz4.frame.decompress(blob), 'lz4-frame'
        except ImportError:
            return None, 'lz4-needs-pip'
    if blob[:4] == b'\x02\x21\x4c\x18':              # lz4 legacy (Android)
        try:
            r = lz4_legacy_decompress(blob)
            if r is None:
                return None, 'lz4-legacy-empty'
            img, nblk = r
            return img, f'lz4-legacy({nblk}blk)'
        except ImportError:
            return None, 'lz4-needs-pip'
        except Exception as e:
            return None, f'lz4-legacy-fail:{e}'
    if blob[:4] == b'\x28\xb5\x2f\xfd':              # zstd frame
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompressobj().decompress(blob), 'zstd'
        except ImportError:
            return None, 'zstd-needs-pip'
    if is_arm64_image(blob):                        # raw uncompressed
        return blob, 'raw'
    return None, 'unknown'


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    d = open(src, 'rb').read()
    print(f'[extract] {src}: {len(d)} bytes', file=sys.stderr)

    ho = find_android_header(d)
    if ho < 0:
        print('[extract] no ANDROID! header — trying raw Image at 0x1000 (v2505a layout)', file=sys.stderr)
        blob = d[0x1000:]
        img, method = try_decompress(blob)
        if img is None and not is_arm64_image(d[0x1000:]):
            print('[extract] FATAL: neither bootimg nor raw Image recognized', file=sys.stderr)
            return 1
    else:
        kernel_size, page_size, hdr_ver = parse_v0(ho, d)
        print(f'[extract] header@{ho:#x} ver={hdr_ver} page={page_size} kernel_size={kernel_size:#x}', file=sys.stderr)
        ko = ho + page_size                       # kernel always page-aligned after header
        blob = d[ko:ko + kernel_size]
        img, method = try_decompress(blob)
        if img is None:
            # some vendors pad; try the whole remainder as fallback
            img2, m2 = try_decompress(d[ko:])
            if img2 is not None:
                img, method = img2, m2
            else:
                print(f'[extract] FATAL: kernel blob not decompressable (method={method})', file=sys.stderr)
                print('[extract] hint: pip install lz4 zstandard', file=sys.stderr)
                return 1
    if not is_arm64_image(img):
        print('[extract] FATAL: decompressed payload is not an arm64 Image (no ARMd @ +0x38)', file=sys.stderr)
        return 1
    open(dst, 'wb').write(img)
    print(f'[extract] OK -> {dst} ({len(img)} bytes, method={method}, magic ARMd verified)', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
