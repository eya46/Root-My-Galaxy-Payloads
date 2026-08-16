# SM-F731U / F731USQS6FZA1 porting record (INCOMPLETE)

Status: exploit reaches the kernel PI deadlock dance and crashes there.
Not yet working. This record contains every verified constant and the exact
failure point so the port can be finished without redoing the derivation.

## 1. Target identity

```text
model: SM-F731U (Galaxy Z Flip 5 US, SM8550)
fingerprint: samsung/b5qsqw/b5q:16/BP2A.250605.031.A3/F731USQS6FZA1:user/release-keys
kernel release: 5.15.178-android13-8-31998796-abF731USQS6FZA1
kernel Image SHA-256: 33bce723053b0a1f3140f2c6facc10f0398c89381c736c0a418b69ca772b40e0
BTF size: 5959221 bytes (cross-checked against on-device /sys/kernel/btf/vmlinux)
```

Firmware downloaded from FUS with samloader-rs 2.0.0 using the exact
four-part version `F731USQS6FZA1/F731UOYN6FZA1/F731USQS6FZA1/F731USQS6FZA1`
(region XAA). Symbols recovered with `vmlinux-to-elf` (base
`0xffffffc008000000` confirmed by multi-symbol caller resolution).

## 2. Verified findings (all live-tested on device)

- **KASLR granularity is 32 KiB, not 64 KiB.** Observed slides: 0x38000,
  0x108000 (per-boot random, `slide & 0x7fff == 0`, some boots are also
  64 KiB-aligned by chance). `slide.c` alignment masks relaxed from
  `0xffff` to `0x7fff` (both the tracefs accept and the forced-offset env
  check). Caller resolution cross-check: `rcu_gp_fqs_loop+0x188` and
  `worker_thread+0x78` from the live trace match the recovered ELF exactly.
- **`SLIDE_TRACEFS_EVENT_ID = 108`**, read live from
  `/sys/kernel/tracing/events/sched/sched_blocked_reason/id`; matches
  `__TRACE_LAST_TYPE(20) + index(88)`.
- **`SLIDE_TRACEFS_WORKER_CALLER_OFF = 0x0010d6ec`** (instruction after
  `bl schedule` at `0xffffffc00810d6e8`).
- **`MM_STRUCT_SZ = 0x400`** (`/proc/slabinfo`: objsize 1024, objperslab 32,
  pagesperslab 8). The `common.h` default 0x500 (6.1 kernels) is WRONG for
  this kernel and crashes `prepare_kernel_page`. Overridden in target.h.
- `struct rt_mutex_base`: raw_spinlock 4 bytes → waiters.rb_node @0x08,
  rb_leftmost @0x10, owner @0x18 — matches the hardcoded fake-lock writes.
- `sizeof(struct mm_struct) = 0x3e0` (BTF; slab stride rounds to 0x400).
- task_struct: usage=0x38 prio=0x7c normal_prio=0x84 sched_task_group=0x400
  pi_lock=0x884 pi_waiters=0x898 pi_top_task=0x8a8 pi_blocked_on=0x8b0
  real_cred=0x790 cred=0x798 (differs from all 6.1 targets).
- `worker_pool.worklist=0x20 nr_idle=0x34` (differs from dm3q 0x28/0x3c).
- rt_mutex_waiter identical to 5.15.189 dm3q (0x58, compact layout).
- `miscdevice.fops=0x10`, `selinux_state.enforcing=0x0`,
  `workqueue_struct.dfl_pwq=0xb0`, configfs_buffer fields unchanged.
- `random_table[]` "boot_id" entry data slot = 0x02ab0338 (value ==
  sysctl_bootid storage at 0x02d1bf31; ctl_table stride 0x38).
- p0 fingerprint regenerated at 32 KiB steps (63 rows) with the patched
  `tools/generate_p0_fingerprint.pl`.

With these, the exploit reliably reaches:
slide leak → mm leak → slab drain → sk_buff reclaim 16/16 →
`prepare_kernel_page` returns → pselect child blocks in `do_select`
(wchan/syscall verified via `/proc/self/task/*/wchan`, `syscall` = 72) →
`FUTEX_WAIT_REQUEUE_PI` timeout (expected).

## 3. Failure point

Immediately after the consumer thread issues `sched_setattr(SCHED_BATCH)`
on the waiter tid (the kernel PI walk into the fake waiter), the kernel
panics. No further payload prints. A `SLIDE_SAFE=1` guard that skips the
`sched_setattr` trigger runs the entire route to completion without any
crash, so the failure is specifically the kernel interpreting the fake
waiter / fake lock / fake task contents.

Remaining suspects, in order:

1. `P0_KERNEL_PHYS_LOAD = 0x80080000` (delta 0x80000, copied from dm3q;
   not verified for this ABL — no sboot.bin; abl.elf contains no plaintext
   load-address constants). Everything routed through `data_addr()` uses it,
   including the waiter's `tree_left`/`pi_left` targets
   (`data_addr(ASHMEM_MISC_FOPS)`).
2. `SKB_DATA_DELTA = -0x1000` (dm3q value; depends on skb headroom layout).
3. `SLIDE_PSELECT_WORD_SHIFT` — currently 0 (derived: waiter words 0-10
   inside the 15-qword logical fdsets). A value of 3 was also tried: clean
   miss (errno 110) with no crash; 0 reaches the PI walk and crashes, which
   suggests placement is correct and the contents/pointers are wrong.
4. 32 KiB slide interacting with an assumption of 64 KiB alignment deeper
   in the oracle/dance path.

## 4. Debug aids added in this tree

- `SLIDE_LEAK_ONLY=1` — stop after the tracefs KASLR leak (safe).
- `SLIDE_SAFE=1` — run the full route but skip the `sched_setattr` PI
  trigger, printing the waiter's wchan/syscall (safe; verified the child
  blocks in `do_select`).
- `SLIDE_WORD_SHIFT=<n>` env override for `SLIDE_PSELECT_WORD_SHIFT`.
- `SLIDE_DEBUG=1` — per-record tracefs parse prints.
- `slide.c` fprintf-based debug prints (pr_error exits the process — do
  not use it for tracing).
- `tools/generate_p0_fingerprint.pl` patched for 0x8000-step slides.

## 5. Firmware-to-target.h values

See `src/targets/f731u-F731USQS6FZA1/target.h`. Symbol offsets (from
`vmlinux.nm`, base 0xffffffc008000000):

```text
INIT_TASK_OFF             0x02afa840   ROOT_TASK_GROUP_OFF   0x02baaac0
SELINUX_ENFORCING_OFF     0x02c7f430   KMALLOC_CACHES_OFF   0x01f9d998
ANON_PIPE_BUF_OPS_OFF     0x01dc8120   SYSTEM_UNBOUND_WQ    0x02990800
CALL_USERMODEHELPER_...   0x00104160   PREPARE_KERNEL_CRED  0x0011e048
COMMIT_CREDS_OFF          0x0011fd84   OVERRIDE_CREDS_OFF   0x0011ee5c
ASHMEM_FOPS_OFF           0x01f46de0   ASHMEM_MISC_FOPS_OFF 0x02af27a8
ASHMEM_IOCTL_OFF          0x010c0834   ASHMEM_COMPAT_IOCTL  0x010c0e90
ASHMEM_MMAP_OFF           0x010c0ee8   ASHMEM_OPEN_OFF      0x010c11c8
ASHMEM_RELEASE_OFF        0x010c1260   ASHMEM_SHOW_FDINFO   0x010c137c
CONFIGFS_READ_ITER_OFF    0x005d5ef0   CONFIGFS_BIN_WRITE  0x005d6918
COPY_SPLICE_READ_OFF      0x00526b64   NOOP_LLSEEK_OFF      0x004b9a28
NFULNL_LOGGER_NAME_OFF    0x01cbad67   NFULNL_LOGGER_OBJECT 0x02991e48
RANDOM_TABLE_BOOT_ID_PTR  0x02ab0338   SYSCTL_BOOTID_OFF    0x02d1bf31
```
