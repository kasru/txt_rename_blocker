#!/bin/bash
# Test suite for txt_rename_blocker.ko
# Tests content-based protection: .txt files with protected header are blocked

PASS=0
FAIL=0
MODULE="txt_rename_blocker"
MODULE_DIR="$(dirname "$(readlink -f "$0")")"
CONFIG_FILE="/etc/txt_rename_blocker.cfg"
PROTECTED_HEADER="PROTECTED_HEADER"  # exactly 16 bytes

log_pass() { echo -e "  \033[32m  PASS: $1\033[0m"; PASS=$((PASS + 1)); }

log_fail() { echo -e "  \033[31m  FAIL: $1\033[0m"; FAIL=$((FAIL + 1)); }

check() {
    local desc="$1" cmd="$2" expect_fail="$3"
    if eval "$cmd" 2>/dev/null; then
        [ "$expect_fail" = "true" ] && log_fail "$desc (should have failed)" || log_pass "$desc"
    else
        [ "$expect_fail" = "true" ] && log_pass "$desc" || log_fail "$desc (unexpected error: $?)"
    fi
}

TDIR=$(mktemp -d /tmp/txt_test_XXXX)

cleanup() {
    rm -rf "$TDIR" 2>/dev/null || true
    sudo rmmod "$MODULE" 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "=== 1. BUILD CHECK ==="
if [ -f "$MODULE_DIR/$MODULE.ko" ]; then
    log_pass "$MODULE.ko built"
else
    log_fail "$MODULE.ko not found"
    echo "=== SKIPPING remaining tests ==="
    exit 1
fi

echo ""
echo "=== 2. WITHOUT CONFIG — NO HEADER, ALL .txt ALLOWED ==="
sudo rm -f "$CONFIG_FILE"
sudo rmmod "$MODULE" 2>/dev/null || true
sudo insmod "$MODULE_DIR/$MODULE.ko"
if lsmod | grep -q "^${MODULE}"; then
    log_pass "module loaded without config"
else
    log_fail "module load without config"
    echo "=== ABORT ==="
    exit 1
fi

printf 'PROTECTED_HEADERextra' > "$TDIR/noconfig.txt"
check "mv .txt without config"    "mv '$TDIR/noconfig.txt' '$TDIR/noconfig.bak'"   false
printf 'ANY_CONTENT_HERE__' > "$TDIR/noconfig2.txt"
check "mv .txt without config (2)" "mv '$TDIR/noconfig2.txt' '$TDIR/noconfig2.bak'" false
sudo rmmod "$MODULE"
log_pass "module unloaded"

echo ""
echo "=== 3. WITH CONFIG — SET UP PROTECTED HEADER ==="
printf '%s' "$PROTECTED_HEADER" | sudo tee "$CONFIG_FILE" > /dev/null
sudo insmod "$MODULE_DIR/$MODULE.ko"
if lsmod | grep -q "^${MODULE}"; then
    log_pass "module loaded with config"
else
    log_fail "module load with config"
fi
CFG_SZ=$(wc -c < "$CONFIG_FILE")
[ "$CFG_SZ" -eq 16 ] && log_pass "config file is 16 bytes" || log_fail "config file size=$CFG_SZ (expected 16)"

echo ""
echo "=== 4. .txt WITH PROTECTED HEADER -> BLOCKED (EPERM) ==="
printf '%sextra' "$PROTECTED_HEADER" > "$TDIR/match.txt"
check "first 16 bytes = PROTECTED_HEADER" "mv '$TDIR/match.txt' '$TDIR/match.bak'" true

printf '%sextra' "$PROTECTED_HEADER" > "$TDIR/match2.txt"
check "second attempt blocked"   "mv '$TDIR/match2.txt' '$TDIR/match2.bak'" true

mkdir -p "$TDIR/sub"
printf '%s' "$PROTECTED_HEADER" > "$TDIR/sub/cross.txt"
check "cross-directory blocked"  "mv '$TDIR/sub/cross.txt' '$TDIR/sub/cross.bak'" true

echo ""
echo "=== 5. .txt WITH DIFFERENT HEADER -> ALLOWED ==="
printf '%-16s' "HEADER_UNMATCHED" > "$TDIR/diff.txt"
check "first 16 bytes != PROTECTED_HEADER" "mv '$TDIR/diff.txt' '$TDIR/diff.bak'" false

printf '%-16s' "SOMETHING_ELSE__" > "$TDIR/diff2.txt"
check "different content allowed" "mv '$TDIR/diff2.txt' '$TDIR/diff2.bak'" false

echo ""
echo "=== 6. .txt SHORTER THAN 16 BYTES -> ALLOWED ==="
printf 'short' > "$TDIR/short.txt"
check "short .txt allowed"        "mv '$TDIR/short.txt' '$TDIR/short.bak'" false

echo ""
echo "=== 7. EMPTY .txt -> ALLOWED ==="
: > "$TDIR/empty.txt"
check "empty .txt allowed"       "mv '$TDIR/empty.txt' '$TDIR/empty.bak'" false

echo ""
echo "=== 8. NON-.txt WITH PROTECTED HEADER -> ALLOWED ==="
printf '%s' "$PROTECTED_HEADER" > "$TDIR/protected.bin"
check "non-.txt with matching header" "mv '$TDIR/protected.bin' '$TDIR/protected.ren'" false

printf '%s' "$PROTECTED_HEADER" > "$TDIR/protected.py"
check ".py with matching header"  "mv '$TDIR/protected.py' '$TDIR/protected.pyc'" false

echo ""
echo "=== 9. CASE SENSITIVITY: .TXT (uppercase) != .txt ==="
printf '%s' "$PROTECTED_HEADER" > "$TDIR/upper.TXT"
check "mv .TXT allowed (case-sensitive)" "mv '$TDIR/upper.TXT' '$TDIR/upper.ren'" false

echo ""
echo "=== 10. SUFFIX CHECK: .txt.bak != .txt ==="
printf '%s' "$PROTECTED_HEADER" > "$TDIR/test.txt.bak"
check "mv .txt.bak allowed"       "mv '$TDIR/test.txt.bak' '$TDIR/test.txt.old'" false

echo ""
echo "=== 11. PROTECTED HEADER IN MIDDLE OF FILE (>16 bytes) -> BLOCKED ==="
printf '%s' "${PROTECTED_HEADER}more_data_here" > "$TDIR/long_match.txt"
check "long .txt with matching prefix blocked" "mv '$TDIR/long_match.txt' '$TDIR/long_match.bak'" true

echo ""
echo "=== 12. CROSS-DIRECTORY WITH PROTECTED HEADER -> BLOCKED ==="
mkdir -p "$TDIR/dira" "$TDIR/dirb"
printf '%s' "$PROTECTED_HEADER" > "$TDIR/dira/x.txt"
check "cross-dir .txt blocked"    "mv '$TDIR/dira/x.txt' '$TDIR/dirb/x.bak'" true

echo ""
echo "=== 13. RELATIVE PATHS — should also work with filp_open + AT_FDCWD ==="
mkdir -p "$TDIR/rel"
printf '%s' "$PROTECTED_HEADER" > "$TDIR/rel/secret.txt"
(cd "$TDIR/rel" && mv secret.txt secret.bak 2>/dev/null)
if [ -f "$TDIR/rel/secret.txt" ]; then
    log_pass "relative path .txt blocked (stays as secret.txt)"
else
    log_fail "relative path .txt was renamed (should be blocked)"
fi

printf 'UNPROTECTED_CONTENT' > "$TDIR/rel/open.txt"
(cd "$TDIR/rel" && mv open.txt open.bak 2>/dev/null)
if [ -f "$TDIR/rel/open.bak" ]; then
    log_pass "relative path non-matching allowed"
else
    log_fail "relative path non-matching was blocked"
fi

echo ""
echo "=== 14. UNLOAD MODULE -> .txt WORKS AGAIN ==="
sudo rmmod "$MODULE"
if ! lsmod | grep -q "^${MODULE}"; then
    log_pass "module unloaded"
else
    log_fail "module still loaded"
fi
printf '%sextra' "$PROTECTED_HEADER" > "$TDIR/after_unload.txt"
check "mv .txt works after unload" "mv '$TDIR/after_unload.txt' '$TDIR/after_unload.bak'" false

echo ""
echo "=== 15. RELOAD / UNLOAD CYCLE ==="
sudo insmod "$MODULE_DIR/$MODULE.ko"
lsmod | grep -q "^${MODULE}" && log_pass "reload" || log_fail "reload failed"
sudo rmmod "$MODULE"
! lsmod | grep -q "^${MODULE}" && log_pass "reload rmmod" || log_fail "reload rmmod failed"

echo ""
echo "=== 16. CLEANUP — remove config ==="
sudo rm -f "$CONFIG_FILE"
log_pass "config removed"

echo ""
echo "==================== RESULTS ===================="
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    echo -e " \033[32m ALL $TOTAL TESTS PASSED\033[0m"
else
    echo -e " \033[31m $FAIL/$TOTAL TESTS FAILED\033[0m"
fi
exit $FAIL
