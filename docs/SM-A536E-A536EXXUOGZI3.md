# SM-A536E A536EXXUOGZI3 profile

This profile targets a Galaxy A53 5G running the firmware and kernel below.

| Field | Value |
| --- | --- |
| Model | `SM-A536E` |
| Device | `a53x` |
| Firmware | `A536EXXUOGZI3` (`OS16`, CSC `A536EOXEOGZI3`) |
| Android | 16 / API 36 |
| Page size | 4096 |
| Kernel | `5.10.246-android12-9-31999025-abA536EXXUOGZI3` |
| Kernel build | `#1 SMP PREEMPT Mon Sep 14 17:54:34 KST 2026`, Samsung clang 12.0.4 |
| GCC/Clang banner | `Linux version 5.10.246-android12-9-31999025-abA536EXXUOGZI3 (dpi@VPHMRB636)` |

The payload is the same source tree as the device-tested
`a53x-A536EXXSNGZG3` profile: split by stage under
`src/targets/a53x-A536EXXUOGZI3/`, with `payload.c` as the app entry point,
`ghostlock.c` as the KASLR slide leak and 64-bit write, `page.c` as the
KernelSnitch discovery and deterministic SLUB/SKB reclaim, and `chain.c` as
ARW validation, modified-state restore, and root-helper launch. The four
sources are byte-identical to the GZG3 build; only `target.h` differs, so the
whole port is the re-derivation of the target constants below.

## Re-derived constants

Every address was re-derived from the firmware's own decompressed kernel image
(`vmlinux` with full `.symtab`). Aliases are the linear-map (page-offset)
addresses the payload computes against, image addresses are the
`KIMAGE_TEXT_BASE`-relative ones.

| Macro | GZG3 (`5.10.237`) | UOGZI3 (`5.10.246`) | Symbol it resolves to |
| --- | --- | --- | --- |
| `INIT_TASK_BASE` | `0xffffff8001e0dd00` | `0xffffff8001e0dd00` | `init_task` (unchanged) |
| `SELINUX_STATE_ALIAS` | `0xffffff80021ddb68` | `0xffffff80021deba8` | `selinux_state` |
| `ASHMEM_MISC_FOPS_ALIAS` | `0xffffff8001ffbc20` | `0xffffff8001ffbee0` | `&ashmem_misc.fops` (`+0x10`) |
| `ASHMEM_FOPS_IMAGE` | `0xffffffc009b06f18` | `0xffffffc009b0af48` | `ashmem_fops` |
| `SYSTEM_UNBOUND_WQ_ALIAS` | `0xffffff8001df9e10` | `0xffffff8001df9e10` | `system_unbound_wq` (unchanged) |
| `PWQ_CACHE_ALIAS` | `0xffffff800207fca8` | `0xffffff8002080ca8` | `pwq_cache` |
| `CALL_USERMODEHELPER_EXEC_WORK_IMAGE` | `0xffffffc0080f6be4` | `0xffffffc0080f6ee0` | `call_usermodehelper_exec_work` |
| `INIT_MM_IMAGE` | `0xffffffc009f64f38` | `0xffffffc009f64f38` | `init_mm` (unchanged) |

The forged file-operations table resolves exactly in this image as well:

| Slot | Address | Symbol |
| --- | --- | --- |
| `0x08` | `0xffffffc008379360` | `noop_llseek` |
| `0x10` | `0xffffffc008448dcc` | `configfs_read_file` |
| `0x18` | `0xffffffc00844922c` | `configfs_write_bin_file` |
| `0x50` | `0xffffffc008c3a7b4` | `ashmem_ioctl` |
| `0x58` | `0xffffffc008c3b108` | `compat_ashmem_ioctl` |
| `0x60` | `0xffffffc008c3b160` | `ashmem_mmap` |
| `0x70` | `0xffffffc008c3b390` | `ashmem_open` |
| `0x80` | `0xffffffc008c3b414` | `ashmem_release` |
| `0xc8` | `0xffffffc0083c465c` | `generic_file_splice_read` |
| `0xe0` | `0xffffffc008c3b534` | `ashmem_show_fdinfo` |

Everything else in `target.h` is layout, not address, and is unchanged from
the GZG3 header: `MM_STRUCT_SZ 0x3c0`, `MM_ORDER 3`, `MM_PARTIALS 5`, the
`CFG_*` configfs group offsets (`0x10/0x50/0x58/0x60/0x64`), the
`PWQ_*`/`POOL_*`/`WORK_*` offsets, `KMEM_CACHE_USERSIZE_OFF 0xf8`, and the
`A536_*` spray parameters. Both releases carry the same Google KMI
(`android12-9-31999025`), and no data-structure layout used by the payload
moved between the two builds: only symbol addresses did.

The build was checked at the instruction level, so the published `.so` cannot
be a stale GZG3 artifact. Clang materializes these 64-bit constants as
`mov xN, #-imm16` plus `movk` halves, so each changed constant has a low half
word that is unique to one release. Every new half word is present in this
artifact and absent from the GZG3 one, and every GZG3 half word is present in
the GZG3 artifact only:

| Constant | UOGZI3 low half | Emitted as | GZG3 low half | Emitted as |
| --- | --- | --- | --- | --- |
| `ASHMEM_FOPS_C8_IMAGE` | `0x465c` | `#-0xb9a4` (2x) | `0x3ad8` | `#-0xc528` (2x) |
| `SELINUX_STATE_ALIAS` | `0xeba8` | `#-0x1458` (2x) | `0xdb68` | `#-0x2498` (2x) |
| `ASHMEM_MISC_FOPS_ALIAS` | `0xbee0` | `#0xbee0` (2x) | `0xbc20` | `#0xbc20` (2x) |
| `ASHMEM_FOPS_IMAGE` | `0xaf48` | `#-0x50b8` | `0x6f18` | `#-0x90e8` |
| `PWQ_CACHE_ALIAS` | `0x0ca8` | `#-0xf358` | `0xfca8` | `#-0x358` |
| `CALL_USERMODEHELPER_EXEC_WORK_IMAGE` | `0x6ee0` | `#-0x9120` | `0x6be4` | `#-0x941c` |
| fops `0x08` | `0x9360` | `#-0x6ca0` (2x) | `0x89dc` | `#-0x7624` (2x) |
| fops `0x10` | `0x8dcc` | `#-0x7234` (2x) | `0x7488` | `#-0x8b78` (2x) |
| fops `0x50` | `0xa7b4` | `#-0x584c` (2x) | `0x78e8` | `#-0x8718` (2x, shared with the GZG3 `0x18` slot) |

The remaining changed slots (`0x18`, `0x58`, `0x60`, `0x70`, `0x80`, `0xe0`)
are materialized relative to another address in the same table (`adrp`/`add`)
rather than as independent 64-bit immediates, so their half words are not
individually observable in either build; they are verified through the
symbol-table mapping above instead.

## KernelSU

`CONFIG_KDP=y` and `CONFIG_SECURITY_DEFEX=y` are set in this build, so the
Samsung KDP module is the only usable one. The 5.10 module is KMI-scoped, and
`A536EXXUOGZI3` and `A536EXXSNGZG3` share the KMI `android12-9-31999025`, so
this profile reuses `kernelsu/ksud-A536EXXSNGZG3-kdp` exactly as the S25U
profiles share one `ksud` (schema version 3 keeps each KernelSU artifact
once).

Reuse is safe because the module carries an allocatable but zero-length
`__versions` section, which is the flag 5.10's `same_magic()` uses to ignore
the release token:

- `find_module_sections()` resolves `__versions` through
  `find_sec()`/`SHF_ALLOC` and stores its section index in `info->index.vers`
  (in this image the store is at `load_module+0x41c`, read back by
  `check_modinfo` as `[info, #0x7c]`); the section is present
  with `SHF_ALLOC` set and size 0, so the index is non-zero.
- `check_modinfo()` then calls `same_magic(modmagic, vermagic,
  info->index.vers)`, and `same_magic()` skips everything up to the first
  space of both strings when the module has crcs. The kernel compares only
  the tail. In this image the release string lives at
  `0xffffffc009968ce0`
  (`5.10.246-android12-9-31999025-abA536EXXUOGZI3 SMP preempt mod_unload modversions aarch64`)
  and the tail pointer the kernel compares against is `0xffffffc009968d0d`,
  i.e. `+45`, immediately past the `-abA536EXXUOGZI3` token. Both release
  tokens are 45 bytes, so the compared tail is byte-identical for the GZG3
  module.
- Undefined imports are resolved from `/proc/kallsyms` by the `ksud`
  `init_module()` loader, not by kernel symbol lookup, so only the import
  names matter. Auditing the GZG3 module against this release's recovered
  `vmlinux` (and its recovered `Module.symvers`, 7214 exports) reports
  `undefined symbols: 202`, `missing from target symbol table: 0`,
  `module version entries: 0`, `target CRC mismatches: 0`.

As with every other profile in this repository, the KernelSU installation is
volatile: no boot image is modified, and a reboot removes it.

## Status

The payload, the re-derived constants, the forged fops table, and the
KernelSU import/module-compatibility audit are verified against this
firmware's kernel image. The full chain has not been run on hardware for this
release yet, so no device screenshots are published for it; the GZG3
validation record in
[`SM-A536E-A536EXXSNGZG3.md`](SM-A536E-A536EXXSNGZG3.md) documents the same
payload logic running end to end on the previous kernel of the same KMI.

## Published artifacts

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `artifacts/a53x-A536EXXUOGZI3/cve-2026-43499-app.so` | 104128 | `fa5fe911a3c2016b4a66519ee519a77c030d6a66b3195485025efd7836dd7189` |
| `kernelsu/android12-5.10_kernelsu-A536EXXSNGZG3-kdp.ko` | 341368 | `ae9d3815c69d708063a77c49470357f2b5b45ba7313cde6cebbf32ae05fa17a8` |
| `kernelsu/ksud-A536EXXSNGZG3-kdp` | 4870752 | `c35130bf54f7b8e3c31eee2349c7e053d1e2878b4d47b21090012523ff02e3ef` |

Rebuild:

```sh
make TARGET=a53x-A536EXXUOGZI3 ANDROID_NDK_HOME=/path/to/android-ndk release
```

The module declares the GZG3 release in its `.modinfo`:

```text
5.10.237-android12-9-31999025-abA536EXXSNGZG3 SMP preempt mod_unload modversions aarch64
```

Its first token is ignored on this kernel for the `__versions` reason above;
only the compared tail matters, and it is identical for both releases.

This profile is exact-build support; it does not claim compatibility with
other Galaxy A53 models, firmware, or kernel releases.
