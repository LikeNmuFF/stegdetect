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
assert_contains "$TMP_DIR/help.out" "Steghide passphrase"
assert_contains "$TMP_DIR/help.out" "STEGDETECT_PASSPHRASE"
assert_contains "$TMP_DIR/help.out" "--passphrase PASS"
assert_contains "$TMP_DIR/help.out" "Zero-width"
assert_contains "$TMP_DIR/help.out" "--recursive DEPTH"
assert_contains "$TMP_DIR/help.out" "--wordlist FILE"

if bash "$SCRIPT" >"$TMP_DIR/empty.out" 2>&1; then
  fail "running without a target should fail"
fi
assert_contains "$TMP_DIR/empty.out" "Usage:"

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

mkdir "$TMP_DIR/hidebin"
cat >"$TMP_DIR/hidebin/steghide" <<'FAKE_STEGHIDE'
#!/usr/bin/env bash
printf 'args: %s\n' "$*"
if [[ "${1:-}" == "extract" ]]; then
  out=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-xf" ]]; then
      out="$2"
      shift 2
    else
      shift
    fi
  done
  [[ -n "$out" ]] && printf '%s\n' 'KLEIA{fake_extracted_payload}' 'prefix FLAG{default_pattern_flag} suffix' >"$out"
fi
exit 0
FAKE_STEGHIDE
chmod +x "$TMP_DIR/hidebin/steghide"
printf '%s\n' 'fake jpeg content' >"$TMP_DIR/sample.jpg"
PATH="$TMP_DIR/hidebin:$PATH" bash "$SCRIPT" --no-install --passphrase 'hunter2' --extract --output "$TMP_DIR/hide-reports" "$TMP_DIR/sample.jpg" >"$TMP_DIR/hide-scan.out"
assert_contains "$TMP_DIR/hide-scan.out" "--- steghide info (passphrase supplied) ---"
assert_contains "$TMP_DIR/hide-scan.out" "-p hunter2"
assert_contains "$TMP_DIR/hide-scan.out" "Extracted steghide payload as printable strings:"
assert_contains "$TMP_DIR/hide-scan.out" "KLEIA{fake_extracted_payload}"
assert_contains "$TMP_DIR/hide-scan.out" "--- flag pattern grep on extracted payload ---"
assert_contains "$TMP_DIR/hide-scan.out" "KLEIA{fake_extracted_payload}"
assert_contains "$TMP_DIR/hide-scan.out" "FLAG{default_pattern_flag}"
assert_contains "$TMP_DIR/hide-scan.out" "brace-delimited hidden text"

PATH="$TMP_DIR/hidebin:$PATH" bash "$SCRIPT" --no-install --passphrase 'hunter2' --extract --flag-pattern 'KLEIA\{[^}]+\}' --output "$TMP_DIR/hide-custom" "$TMP_DIR/sample.jpg" >"$TMP_DIR/hide-custom.out"
assert_contains "$TMP_DIR/hide-custom.out" "--- flag pattern grep on extracted payload ---"
assert_contains "$TMP_DIR/hide-custom.out" "KLEIA{fake_extracted_payload}"
awk '/--- flag pattern grep on extracted payload ---/{flag=1; next} /--- custom pattern grep ---/{flag=0} flag' "$TMP_DIR/hide-custom.out" >"$TMP_DIR/flaggrep-section.txt"
if grep -F -- 'FLAG{default_pattern_flag}' "$TMP_DIR/flaggrep-section.txt" >/dev/null; then
  fail "custom pattern should not match the default FLAG{} form"
fi

PATH="$TMP_DIR/hidebin:$PATH" bash "$SCRIPT" --no-install --extract --output "$TMP_DIR/hide-nopass" "$TMP_DIR/sample.jpg" >"$TMP_DIR/hide-nopass.out"
assert_contains "$TMP_DIR/hide-nopass.out" "--- steghide info (no passphrase) ---"
assert_contains "$TMP_DIR/hide-nopass.out" "extraction skipped: --extract needs --passphrase"

printf '%s\n' 'fake png content' >"$TMP_DIR/sample.png"
PATH="$TMP_DIR/hidebin:$PATH" bash "$SCRIPT" --no-install --output "$TMP_DIR/hide-png" "$TMP_DIR/sample.png" >"$TMP_DIR/hide-png.out"
assert_contains "$TMP_DIR/hide-png.out" "skipped: steghide cover files must be JPEG, BMP, WAV, or AU"

# --- OCR on still images and extracted video frames ---
mkdir "$TMP_DIR/ocrbin"
cat >"$TMP_DIR/ocrbin/tesseract" <<'FAKE_TESSERACT'
#!/usr/bin/env bash
case "$(basename "$1")" in
  ocr-sample.png) printf '%s\n' 'IMAGEFLAG{ocr_image_found}' ;;
  frame_*.png) printf '%s\n' 'VIDEOFLAG{ocr_video_found}' ;;
esac
FAKE_TESSERACT
cat >"$TMP_DIR/ocrbin/ffmpeg" <<'FAKE_FFMPEG'
#!/usr/bin/env bash
output=""
for arg in "$@"; do
  case "$arg" in *.png) output="$arg" ;; esac
done
mkdir -p "$(dirname "$output")"
printf 'frame one\n' >"$(printf '%s' "$output" | sed 's/%04d/0001/')"
printf 'frame two\n' >"$(printf '%s' "$output" | sed 's/%04d/0002/')"
FAKE_FFMPEG
chmod +x "$TMP_DIR/ocrbin/tesseract" "$TMP_DIR/ocrbin/ffmpeg"
printf 'fake png content\n' >"$TMP_DIR/ocr-sample.png"
printf 'fake video content\n' >"$TMP_DIR/ocr-sample.mp4"
PATH="$TMP_DIR/ocrbin:$PATH" bash "$SCRIPT" --no-install --ocr-lang eng --output "$TMP_DIR/ocr-image-reports" "$TMP_DIR/ocr-sample.png" >"$TMP_DIR/ocr-image.out"
assert_contains "$TMP_DIR/ocr-image.out" "--- tesseract OCR ---"
assert_contains "$TMP_DIR/ocr-image.out" "IMAGEFLAG{ocr_image_found}"
PATH="$TMP_DIR/ocrbin:$PATH" bash "$SCRIPT" --no-install --video-fps 2 --output "$TMP_DIR/ocr-video-reports" "$TMP_DIR/ocr-sample.mp4" >"$TMP_DIR/ocr-video.out"
assert_contains "$TMP_DIR/ocr-video.out" "OCR text detected in 2 video frame(s)."
assert_contains "$TMP_DIR/ocr-video.out" "VIDEOFLAG{ocr_video_found}"

# --video-all-frames must override a supplied sampling rate.
PATH="$TMP_DIR/ocrbin:$PATH" bash "$SCRIPT" --no-install --video-fps 2 --video-all-frames --output "$TMP_DIR/ocr-all-frames-reports" "$TMP_DIR/ocr-sample.mp4" >"$TMP_DIR/ocr-all-frames.out"
assert_contains "$TMP_DIR/ocr-all-frames.out" "Extracted 2 frame(s) (all frames)."

# --- zero-width character scan ---
printf 'normal\nhidden\xE2\x80\x8B\xE2\x80\x8B\xE2\x80\x8C\xE2\x80\x8D inside\n' >"$TMP_DIR/zw.txt"
bash "$SCRIPT" --no-install --output "$TMP_DIR/zw-reports" "$TMP_DIR/zw.txt" >"$TMP_DIR/zw-scan.out"
assert_contains "$TMP_DIR/zw-scan.out" "--- zero-width character scan ---"
assert_contains "$TMP_DIR/zw-scan.out" "ZWSP x2, ZWNJ x1, ZWJ x1"

# --- extended decoders ---
cat >"$TMP_DIR/dec.txt" <<'DECEOF'
.... . .-.. .-.. --- / .-- --- .-. .-.. -..
Hello%20world%20encoded%20here%20ok
DECEOF
bash "$SCRIPT" --no-install --output "$TMP_DIR/dec-reports" "$TMP_DIR/dec.txt" >"$TMP_DIR/dec-scan.out"
assert_contains "$TMP_DIR/dec-scan.out" "Morse decodes to readable text: HELLOWORLD"
assert_contains "$TMP_DIR/dec-scan.out" "URL-encoded"

# --- polyglot / magic mismatch ---
printf 'plain text, no magic\n' >"$TMP_DIR/plain.gif"
bash "$SCRIPT" --no-install --output "$TMP_DIR/poly-reports" "$TMP_DIR/plain.gif" >"$TMP_DIR/poly-scan.out"
assert_contains "$TMP_DIR/poly-scan.out" "--- polyglot / magic mismatch ---"
assert_contains "$TMP_DIR/poly-scan.out" "Name suggests: image/gif | Content is: text/plain"

# --- steghide wordlist crack (fallback loop with fake steghide) ---
mkdir "$TMP_DIR/crackbin"
cat >"$TMP_DIR/crackbin/steghide" <<'FAKE_CRACK_STEGHIDE'
#!/usr/bin/env bash
printf 'args: %s\n' "$*"
exit 0
FAKE_CRACK_STEGHIDE
chmod +x "$TMP_DIR/crackbin/steghide"
cat >"$TMP_DIR/hidebin/steghide" <<'FAKE_CRACK_STEGHIDE_OUT'
#!/usr/bin/env bash
# Wordlist mode: the third candidate is the one that works.
if [[ "${1:-}" == "info" ]]; then
  pass=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-p" ]]; then
      pass="$2"
      shift 2
    else
      shift
    fi
  done
  if [[ "$pass" == "goodpass" ]]; then
    printf 'cracked info output\n'
    exit 0
  fi
  exit 1
fi
if [[ "${1:-}" == "extract" ]]; then
  out=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-xf" ]]; then
      out="$2"
      shift 2
    else
      shift
    fi
  done
  [[ -n "$out" ]] && printf '%s\n' 'FLAG{cracked_payload}' >"$out"
fi
exit 0
FAKE_CRACK_STEGHIDE_OUT
chmod +x "$TMP_DIR/hidebin/steghide"
printf 'wrong1\nwrong2\ngoodpass\nwrong3\n' >"$TMP_DIR/wordlist.txt"
PATH="$TMP_DIR/hidebin:$PATH" bash "$SCRIPT" --no-install --wordlist "$TMP_DIR/wordlist.txt" --output "$TMP_DIR/crack-reports" "$TMP_DIR/sample.jpg" >"$TMP_DIR/crack-scan.out"
assert_contains "$TMP_DIR/crack-scan.out" "--- steghide passphrase crack ---"
assert_contains "$TMP_DIR/crack-scan.out" "Passphrase found: goodpass"
assert_contains "$TMP_DIR/crack-scan.out" "FLAG{cracked_payload}"

# --- recursive nested scan with fake binwalk that extracts a real-looking zip ---
mkdir "$TMP_DIR/bwbin"
cat >"$TMP_DIR/bwbin/binwalk" <<'FAKE_BINWALK'
#!/usr/bin/env bash
case " $* " in
  *' --directory='*)
    # Extraction invocation: emit a file with genuine ZIP magic so the
    # scanner's MIME filter accepts it for nested scanning.
    dir=""
    for a in "$@"; do
      case "$a" in --directory=*) dir="${a#--directory=}" ;; esac
    done
    mkdir -p "$dir"
    printf 'PK\x03\x04nested zip payload FLAG{nested_flag_found}\n' >"$dir/payload.bin"
    exit 0
    ;;
  *)
    printf 'DECIMAL       HEXADECIMAL     DESCRIPTION\n'
    printf '0             0x0000          Zip archive data\n'
    ;;
esac
FAKE_BINWALK
chmod +x "$TMP_DIR/bwbin/binwalk"
PATH="$TMP_DIR/bwbin:$PATH" bash "$SCRIPT" --no-install --recursive 1 --output "$TMP_DIR/recur-reports" "$TMP_DIR/sample.jpg" >"$TMP_DIR/recur-scan.out" 2>&1
assert_contains "$TMP_DIR/recur-scan.out" "Queued 1 extracted file(s) for nested scans (depth 1)"
assert_contains "$TMP_DIR/recur-scan.out" "Depth: 1 (nested scan)"
test -f "$TMP_DIR/recur-reports"/stegdetect_report_nested1_nested_d1_1_payload.bin.txt || fail "expected nested1 report for payload.bin"
assert_contains "$TMP_DIR/recur-reports/stegdetect_report_nested1_nested_d1_1_payload.bin.txt" "FLAG{nested_flag_found}"

# --- 7z archive recursion ---
mkdir "$TMP_DIR/sevenbin"
cat >"$TMP_DIR/sevenbin/7z" <<'FAKE_7Z'
#!/usr/bin/env bash
out=$(printf '%s' "$4" | cut -c3-)
mkdir -p "$out/clues"
printf '%s\n' 'FLAG{seven_zip_nested}' >"$out/clues/flag.txt"
FAKE_7Z
chmod +x "$TMP_DIR/sevenbin/7z"
printf 'fake 7z content\n' >"$TMP_DIR/archive.7z"
PATH="$TMP_DIR/sevenbin:/usr/bin:/bin" bash "$SCRIPT" --no-install --recursive 1 --output "$TMP_DIR/seven-reports" "$TMP_DIR/archive.7z" >"$TMP_DIR/seven.out"
assert_contains "$TMP_DIR/seven.out" "Archive unpacked: queued 1 member(s)"
assert_contains "$TMP_DIR/seven-reports/stegdetect_report_nested1_nested_d1_1_flag.txt.txt" "FLAG{seven_zip_nested}"

# --- PDF checks ---
printf '%%PDF-1.4\n1 0 obj << /JavaScript (x) /OpenAction 1 0 R >> endobj\n%%%%EOF\n' >"$TMP_DIR/doc.pdf"
bash "$SCRIPT" --no-install --output "$TMP_DIR/pdf-reports" "$TMP_DIR/doc.pdf" >"$TMP_DIR/pdf-scan.out"
assert_contains "$TMP_DIR/pdf-scan.out" "--- PDF checks ---"
assert_contains "$TMP_DIR/pdf-scan.out" "Suspicious PDF keywords found:"
assert_contains "$TMP_DIR/pdf-scan.out" "/JavaScript"

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
