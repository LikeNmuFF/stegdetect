#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/stegdetect.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_contains() {
  local file="$1"
  local needle="$2"
  grep -F -- "$needle" "$file" >/dev/null || fail "expected '$needle' in $file"
}

bash "$SCRIPT" --help >"$TMP_DIR/help.out"
assert_contains "$TMP_DIR/help.out" "Usage:"
assert_contains "$TMP_DIR/help.out" "--install"
assert_contains "$TMP_DIR/help.out" "--output DIR"
assert_contains "$TMP_DIR/help.out" "--deep"
assert_contains "$TMP_DIR/help.out" "Suspicious text analysis"

if bash "$SCRIPT" >/tmp/stegdetect-empty.out 2>&1; then
  fail "running without a target should fail"
fi
assert_contains /tmp/stegdetect-empty.out "Usage:"

mkdir "$TMP_DIR/fakebin"
cat >"$TMP_DIR/fakebin/sudo" <<'FAKE_SUDO'
#!/usr/bin/env bash
exec "$@"
FAKE_SUDO
chmod +x "$TMP_DIR/fakebin/sudo"

INSTALL_DIR="$TMP_DIR/bin" PATH="$TMP_DIR/fakebin:$PATH" bash "$SCRIPT" --install >"$TMP_DIR/install.out"
test -x "$TMP_DIR/bin/stegdetect" || fail "expected installed command to be executable"
assert_contains "$TMP_DIR/install.out" "Installed stegdetect"

printf '%s\n' 'cG93ZXJzaGVsbCAtbm9wIC1lbmMgQUJDRA==' 'uggc://rknzcyr.pbz/c2' >"$TMP_DIR/suspicious.txt"
bash "$SCRIPT" --no-install --output "$TMP_DIR/reports" "$TMP_DIR/suspicious.txt" >"$TMP_DIR/scan.out"
assert_contains "$TMP_DIR/scan.out" "base64 decodes to readable text"
assert_contains "$TMP_DIR/scan.out" "powershell"
assert_contains "$TMP_DIR/scan.out" "ROT13-readable text"

mkdir "$TMP_DIR/qrbin"
cat >"$TMP_DIR/qrbin/zbarimg" <<'FAKE_ZBARIMG'
#!/usr/bin/env bash
printf '%s\n' 'QR-Code:https://malicious.example.com/drop?cmd=cG93ZXJzaGVsbA=='
FAKE_ZBARIMG
chmod +x "$TMP_DIR/qrbin/zbarimg"
PATH="$TMP_DIR/qrbin:$PATH" bash "$SCRIPT" --no-install --output "$TMP_DIR/qr-reports" "$TMP_DIR/suspicious.txt" >"$TMP_DIR/qr-scan.out"
assert_contains "$TMP_DIR/qr-scan.out" "--- QR code scan ---"
assert_contains "$TMP_DIR/qr-scan.out" "https://malicious.example.com/drop?cmd=cG93ZXJzaGVsbA=="
assert_contains "$TMP_DIR/qr-scan.out" "[suspicious] URL: https://malicious.example.com/drop?cmd=cG93ZXJzaGVsbA=="

mkdir "$TMP_DIR/snowbin"
cat >"$TMP_DIR/snowbin/stegsnow" <<'FAKE_STEGSNOW'
#!/usr/bin/env bash
printf '%s\n' 'Hidden message: powershell -nop'
FAKE_STEGSNOW
chmod +x "$TMP_DIR/snowbin/stegsnow"
PATH="$TMP_DIR/snowbin:$PATH" bash "$SCRIPT" --no-install --output "$TMP_DIR/snow-reports" "$TMP_DIR/suspicious.txt" >"$TMP_DIR/snow-scan.out"
assert_contains "$TMP_DIR/snow-scan.out" "--- stegsnow whitespace scan ---"
assert_contains "$TMP_DIR/snow-scan.out" "Hidden message: powershell -nop"
assert_contains "$TMP_DIR/snow-scan.out" "[high] possible shell execution: powershell"

mkdir "$TMP_DIR/audiobin"
cat >"$TMP_DIR/audiobin/mediainfo" <<'FAKE_MEDIAINFO'
#!/usr/bin/env bash
printf '%s\n' 'Format : Wave' 'Duration : 00:00:01'
FAKE_MEDIAINFO
cat >"$TMP_DIR/audiobin/sox" <<'FAKE_SOX'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    out="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$out" ]] && printf '%s\n' 'fake spectrogram' >"$out"
FAKE_SOX
chmod +x "$TMP_DIR/audiobin/mediainfo" "$TMP_DIR/audiobin/sox"
printf '%s\n' 'fake wave content' >"$TMP_DIR/sample.wav"
PATH="$TMP_DIR/audiobin:$PATH" bash "$SCRIPT" --no-install --output "$TMP_DIR/audio-reports" "$TMP_DIR/sample.wav" >"$TMP_DIR/audio-scan.out"
assert_contains "$TMP_DIR/audio-scan.out" "--- mediainfo (media metadata) ---"
assert_contains "$TMP_DIR/audio-scan.out" "Format : Wave"
assert_contains "$TMP_DIR/audio-scan.out" "--- sox spectrogram ---"
assert_contains "$TMP_DIR/audio-scan.out" "Spectrogram saved to:"
test -f "$TMP_DIR/audio-reports/stegdetect_spectrogram_sample.wav.png" || fail "expected audio spectrogram image"

mkdir "$TMP_DIR/wrapperbin"
cat >"$TMP_DIR/wrapperbin/stegdetect" <<'FAKE_WRAPPER'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "stegdetect.sh 0.2.0"
  exit 0
fi
exit 2
FAKE_WRAPPER
chmod +x "$TMP_DIR/wrapperbin/stegdetect"
PATH="$TMP_DIR/wrapperbin:$PATH" bash "$SCRIPT" --no-install --output "$TMP_DIR/reports2" "$TMP_DIR/suspicious.txt" >"$TMP_DIR/wrapper-check.out"
assert_contains "$TMP_DIR/wrapper-check.out" "[missing] stegdetect JPEG scanner"

echo "All CLI tests passed"
