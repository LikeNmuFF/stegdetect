#!/usr/bin/env bash
#
# stegdetect.sh - steganography and suspicious text triage tool.
#
# This script orchestrates common steganography/forensics tools for images,
# text files, and audio files. It collects raw and decoded text, then highlights
# indicators such as base64, hex blobs, ROT13, URLs, shell commands, and
# malware-like strings. It never executes discovered payloads.

set -uo pipefail

VERSION="0.4.0"
FLAG_PATTERN='FLAG\{[^}]*\}|CTF\{[^}]*\}|flag\{[^}]*\}'
TARGET=""
AUTO_YES=0
PROMPT_INSTALL=1
DO_DECODE=1
DEEP_SCAN=0
STEGHIDE_PASS="${STEGDETECT_PASSPHRASE:-}"
STEGHIDE_EXTRACT=0
OUTPUT_DIR="."
INSTALL_SELF=0
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
COMMAND_NAME="${COMMAND_NAME:-stegdetect}"

if [[ -t 1 ]]; then
  BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'
else
  BOLD=''; GREEN=''; YELLOW=''; RED=''; RESET=''
fi

usage() {
  cat <<'EOF'
Usage:
  stegdetect.sh [OPTIONS] <file-or-directory>
  stegdetect.sh --install

Scan images, text files, and audio files for steganography indicators, embedded
content, metadata clues, printable strings, encoded text, and malicious-looking
suspicious text.

Options:
  -h, --help              Show this manual.
  --version               Show version.
  --install               Install this tool as a root-accessible command.
  --install-dir DIR       Install directory for --install.
                          Default: /usr/local/bin
  --command-name NAME     Installed command name. Default: stegdetect
  --output DIR            Directory for report files. Default: current directory.
  --flag-pattern REGEX    Extra regex to search in raw and decoded text.
                          Default: common FLAG{}, CTF{}, flag{} forms.
  --no-decode             Disable base64, hex, and ROT13 decode attempts.
  --deep                  Run exhaustive stego checks such as zsteg -a.
  --passphrase PASS       Passphrase for steghide info and extraction attempts.
                          Also read from STEGDETECT_PASSPHRASE. Never printed.
  --extract               With --passphrase, extract embedded steghide data into
                          a temporary directory, preview its printable strings, and
                          grep them for the flag pattern. The extracted payload is
                          deleted after the scan.
  --no-install            Do not prompt to install missing scanner tools.
  -y, --yes               Answer yes to dependency install prompts.

Suspicious text analysis:
  Detects base64, long hex strings, ROT13-readable strings, URLs, domains,
  IP addresses, emails, shell commands, script snippets, and common suspicious
  indicators such as powershell, cmd.exe, curl, wget, eval, /bin/sh, and base64 -d.
  QR/barcode payloads are scanned with zbarimg when it is installed.
  Whitespace stego is scanned with stegsnow when it is installed.
  Audio metadata and spectrograms are generated with mediainfo and sox when available.
  Decode attempts are reporting-only and never execute decoded content.

Steghide passphrase:
  steghide cannot confirm or reveal embedded data without a passphrase. Supply one
  with --passphrase, or through the STEGDETECT_PASSPHRASE environment variable, which
  keeps the value out of your shell history and the process list.

    stegdetect.sh --passphrase 'hunter2' cover.jpg
      Reports the embedded file name, size, cipher, and compression.
    stegdetect.sh --passphrase 'hunter2' --extract cover.jpg
      Also prints the embedded payload's printable strings and greps them
      for the flag pattern (default or --flag-pattern).
    STEGDETECT_PASSPHRASE='hunter2' stegdetect cover.wav
      Same as --passphrase, without the value on the command line.

  Steghide cover files must be JPEG, BMP, WAV, or AU; anything else is skipped.
  Use plain PCM WAV, since steghide rejects WAVE_FORMAT_EXTENSIBLE (FormatTag 0xFFFE).
  The passphrase is never written to the report, and --extract writes only into a
  temporary directory that is removed after the scan.

Examples:
  stegdetect.sh image.png
  stegdetect.sh samples/
  stegdetect.sh --output reports image.jpg
  stegdetect.sh --flag-pattern 'secret\{[^}]+\}' image.png
  stegdetect.sh --passphrase 'hunter2' --extract cover.jpg
  stegdetect.sh --passphrase 'hunter2' --extract --flag-pattern 'KLEIA\{[^}]+\}' cover.wav
  sudo ./stegdetect.sh --install
  stegdetect image.png
EOF
}

die() {
  echo "Error: $*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

section() {
  echo -e "\n${BOLD}==== $1 ====${RESET}"
}

real_path() {
  if have readlink; then
    readlink -f "$1" 2>/dev/null || printf '%s\n' "$1"
  else
    printf '%s\n' "$1"
  fi
}

find_external_command() {
  local name="$1"
  local self_real
  self_real="$(real_path "$0")"

  if ! have "$name"; then
    return 1
  fi

  local candidate
  while IFS= read -r candidate; do
    [[ -z "$candidate" ]] && continue
    if [[ "$(real_path "$candidate")" != "$self_real" ]] && ! is_stegdetect_wrapper "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(type -a -P "$name" 2>/dev/null)

  return 1
}

is_stegdetect_wrapper() {
  local candidate="$1"
  local version=""

  if [[ ! -x "$candidate" ]]; then
    return 1
  fi

  version="$("$candidate" --version 2>/dev/null || true)"
  [[ "$version" == stegdetect.sh\ * ]]
}

safe_grep() {
  local pattern="$1"
  grep -E "$pattern" 2>/dev/null || true
}

safe_filename() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

install_self() {
  local src dest
  src="$(real_path "$0")"
  mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
  dest="$INSTALL_DIR/$COMMAND_NAME"

  if [[ -w "$INSTALL_DIR" ]]; then
    cp "$src" "$dest"
    chmod 0755 "$dest"
  else
    sudo cp "$src" "$dest"
    sudo chmod 0755 "$dest"
  fi

  echo -e "${GREEN}Installed stegdetect to: $dest${RESET}"
  echo "Run it from any directory with: $COMMAND_NAME <image-or-directory>"
}

install_tool() {
  local tool="$1"
  case "$tool" in
    file)
      sudo apt update
      sudo apt install -y file
      ;;
    exiftool)
      sudo apt update
      sudo apt install -y libimage-exiftool-perl
      ;;
    binwalk)
      sudo apt update
      sudo apt install -y binwalk
      ;;
    zbarimg)
      sudo apt update
      sudo apt install -y zbar-tools
      ;;
    stegsnow)
      sudo apt update
      sudo apt install -y stegsnow
      ;;
    mediainfo)
      sudo apt update
      sudo apt install -y mediainfo
      ;;
    sox)
      sudo apt update
      sudo apt install -y sox
      ;;
    steghide)
      sudo apt update
      sudo apt install -y steghide
      ;;
    strings)
      sudo apt update
      sudo apt install -y binutils
      ;;
    python3)
      sudo apt update
      sudo apt install -y python3
      ;;
    zsteg)
      if ! have ruby; then
        sudo apt update
        sudo apt install -y ruby
      fi
      sudo gem install zsteg
      ;;
    jsteg)
      echo -e "${YELLOW}jsteg has no apt package. Installing the upstream prebuilt binary.${RESET}"
      sudo apt update
      sudo apt install -y wget
      sudo wget -O /usr/local/bin/jsteg https://github.com/lukechampine/jsteg/releases/download/v0.1.0/jsteg-linux-amd64
      sudo chmod +x /usr/local/bin/jsteg
      ;;
    stegdetect)
      echo -e "${YELLOW}The JPEG stegdetect scanner usually needs to be built from source.${RESET}"
      local ans=""
      if [[ "$AUTO_YES" -eq 1 ]]; then
        ans="y"
      else
        read -rp "Build it now into ./stegdetect-src ? [y/N] " ans
      fi
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        sudo apt update
        sudo apt install -y build-essential libjpeg-dev git util-linux
        if [[ ! -d stegdetect-src ]]; then
          git clone https://github.com/abeluck/stegdetect.git stegdetect-src
        fi
        (
          cd stegdetect-src || exit 1
          linux32 ./configure 2>/dev/null && linux32 make 2>/dev/null || { ./configure && make; }
        )
        if [[ -x ./stegdetect-src/stegdetect ]]; then
          sudo cp ./stegdetect-src/stegdetect /usr/local/bin/stegdetect-bin
          sudo chmod +x /usr/local/bin/stegdetect-bin
          echo -e "${GREEN}Installed JPEG scanner to /usr/local/bin/stegdetect-bin.${RESET}"
          echo "The wrapper will use stegdetect-bin to avoid command-name recursion."
        else
          echo -e "${RED}Build failed. Install manually or run this check without the JPEG scanner.${RESET}"
        fi
      fi
      ;;
    *)
      echo "No known install method for $tool"
      ;;
  esac
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --version)
        echo "stegdetect.sh $VERSION"
        exit 0
        ;;
      --install)
        INSTALL_SELF=1
        shift
        ;;
      --install-dir)
        [[ $# -ge 2 ]] || die "--install-dir requires a directory"
        INSTALL_DIR="$2"
        shift 2
        ;;
      --command-name)
        [[ $# -ge 2 ]] || die "--command-name requires a name"
        COMMAND_NAME="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || die "--output requires a directory"
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --flag-pattern)
        [[ $# -ge 2 ]] || die "--flag-pattern requires a regex"
        FLAG_PATTERN="$2"
        shift 2
        ;;
      --no-decode)
        DO_DECODE=0
        shift
        ;;
      --deep)
        DEEP_SCAN=1
        shift
        ;;
      --passphrase)
        [[ $# -ge 2 ]] || die "--passphrase requires a value"
        STEGHIDE_PASS="$2"
        shift 2
        ;;
      --extract)
        STEGHIDE_EXTRACT=1
        shift
        ;;
      --no-install)
        PROMPT_INSTALL=0
        shift
        ;;
      -y|--yes)
        AUTO_YES=1
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        die "unknown option: $1"
        ;;
      *)
        if [[ -n "$TARGET" ]]; then
          die "only one target may be scanned at a time"
        fi
        TARGET="$1"
        shift
        ;;
    esac
  done
}

analyze_text() {
  local source_file="$1"
  local text_file="$2"
  local report="$3"

  if ! have python3; then
    {
      echo
      echo "--- suspicious text analysis ---"
      echo "Skipped: python3 is missing."
    } | tee -a "$report"
    return 0
  fi

  python3 - "$source_file" "$text_file" "$FLAG_PATTERN" "$DO_DECODE" <<'PY' | tee -a "$report"
import base64
import binascii
import codecs
import math
import re
import string
import sys
from collections import Counter

source_file, text_file, flag_pattern, do_decode_raw = sys.argv[1:5]
do_decode = do_decode_raw == "1"

try:
    raw_text = open(text_file, "r", encoding="utf-8", errors="ignore").read()
except OSError as exc:
    print("\n--- suspicious text analysis ---")
    print(f"Skipped: cannot read collected text: {exc}")
    raise SystemExit(0)

lines = []
for line in raw_text.splitlines():
    cleaned = line.strip()
    if len(cleaned) >= 4:
        lines.append(cleaned)

print("\n--- suspicious text analysis ---")
if not lines:
    print("No printable candidate text collected.")
    raise SystemExit(0)

combined = "\n".join(lines)

patterns = [
    ("high", "possible shell execution", re.compile(r"(?i)\b(powershell|cmd\.exe|wscript|cscript|bash\s+-c|sh\s+-c|/bin/sh|/bin/bash)\b")),
    ("high", "download or remote execution", re.compile(r"(?i)\b(curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin)\b")),
    ("high", "code evaluation or decode execution", re.compile(r"(?i)\b(eval|exec|system|base64\s+-d|frombase64string)\b")),
    ("suspicious", "URL", re.compile(r"(?i)\bhttps?://[^\s\"'<>]+")),
    ("suspicious", "domain", re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz)\b")),
    ("suspicious", "IP address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("info", "email address", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
]

findings = []
seen = set()

def add(severity, kind, value, detail=""):
    value = value.strip()
    if not value:
        return
    if len(value) > 180:
        value = value[:177] + "..."
    key = (severity, kind, value, detail)
    if key not in seen:
        seen.add(key)
        findings.append((severity, kind, value, detail))

def entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())

for severity, kind, regex in patterns:
    for match in regex.finditer(combined):
        add(severity, kind, match.group(0))

try:
    flag_regex = re.compile(flag_pattern)
    for match in flag_regex.finditer(combined):
        add("high", "custom/flag pattern", match.group(0))
except re.error as exc:
    add("info", "invalid custom regex", flag_pattern, str(exc))

base64_regex = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
hex_regex = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32,})(?![A-Fa-f0-9])")
printable = set(string.printable)

decode_results = []

def readable_score(s):
    if not s:
        return 0.0
    good = sum(1 for ch in s if ch in printable and ch not in "\x0b\x0c")
    return good / len(s)

def text_likeness(s):
    if not s:
        return 0.0
    letters = sum(1 for ch in s if ch.isalpha())
    spaces = sum(1 for ch in s if ch.isspace())
    punctuation = sum(1 for ch in s if ch in "/:._-?=&{}[]()")
    return (letters + spaces + punctuation) / len(s)

def plausible_base64_token(token):
    if len(token) < 20:
        return False
    if len(token.rstrip("=")) % 4 == 1:
        return False
    if re.fullmatch(r"[A-Fa-f0-9]+", token.rstrip("=")):
        return False
    unique = len(set(token.rstrip("=")))
    if unique < 6:
        return False
    has_lower = any(ch.islower() for ch in token)
    has_upper = any(ch.isupper() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    has_symbol = any(ch in "+/" for ch in token)
    if sum([has_lower, has_upper, has_digit, has_symbol]) < 2:
        return False
    return entropy(token.rstrip("=")) >= 3.4

def remember_decode(kind, original, decoded):
    compact = " ".join(decoded.split())
    if len(compact) < 4:
        return
    score = readable_score(compact)
    if score < 0.92 or text_likeness(compact) < 0.55:
        return
    decode_results.append((kind, original[:80], compact[:240]))
    add("suspicious", f"{kind} decodes to readable text", compact)

for match in base64_regex.finditer(combined):
    token = match.group(0)
    if not plausible_base64_token(token):
        continue
    decoded_count = len(decode_results)
    if do_decode:
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            decoded = base64.b64decode(padded, validate=True)
            remember_decode("base64", token, decoded.decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    if len(decode_results) > decoded_count:
        add("suspicious", "base64-looking text", token)
    elif not do_decode and entropy(token.rstrip("=")) >= 4.4:
        add("suspicious", "base64-looking text", token)

for match in hex_regex.finditer(combined):
    token = match.group(0)
    if len(set(token.lower())) < 6 or entropy(token) < 3.0:
        continue
    add("suspicious", "hex-looking text", token)
    if do_decode and len(token) % 2 == 0:
        try:
            decoded = bytes.fromhex(token)
            remember_decode("hex", token, decoded.decode("utf-8", errors="ignore"))
        except ValueError:
            pass

wordish = re.compile(r"[A-Za-z][A-Za-z0-9_/@:.,+=-]{11,}")
for match in wordish.finditer(combined):
    token = match.group(0)
    if any(marker in token.lower() for marker in ("c2pa", "jumbf", "xmp:iid", "urn:c2pa")):
        continue
    ent = entropy(token)
    if len(token) >= 24 and ent >= 4.2:
        add("suspicious", "high-entropy/gibberish-looking string", token, f"entropy={ent:.2f}")
    if do_decode:
        rot = codecs.decode(token, "rot_13")
        if re.search(r"(?i)\b(the|flag|http|secret|password|powershell|cmd|shell|admin)\b", rot):
            add("suspicious", "ROT13-readable text", rot, f"from={token[:80]}")

for match in re.finditer(r"\b[A-Za-z0-9_.-]{2,32}\{[^}\r\n]{3,120}\}", combined):
    add("high", "brace-delimited hidden text", match.group(0))

order = {"high": 0, "suspicious": 1, "info": 2}
findings.sort(key=lambda item: (order.get(item[0], 9), item[1], item[2]))

if not findings:
    print("No obvious suspicious text indicators found.")
else:
    for severity, kind, value, detail in findings[:80]:
        suffix = f" ({detail})" if detail else ""
        print(f"[{severity}] {kind}: {value}{suffix}")
    if len(findings) > 80:
        print(f"... {len(findings) - 80} additional findings omitted from terminal report.")

if decode_results:
    print("\nDecoded previews:")
    for kind, original, decoded in decode_results[:20]:
        print(f"- {kind}: {original} -> {decoded}")
elif do_decode:
    print("\nDecoded previews: none.")
else:
    print("\nDecoded previews: disabled by --no-decode.")
PY
}

build_file_list() {
  FILES=()
  if [[ -d "$TARGET" ]]; then
    while IFS= read -r -d '' f; do
      FILES+=("$f")
    done < <(find "$TARGET" -type f \( \
      -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.bmp' -o -iname '*.gif' -o -iname '*.webp' -o -iname '*.tif' -o -iname '*.tiff' \
      -o -iname '*.txt' -o -iname '*.md' -o -iname '*.log' -o -iname '*.csv' -o -iname '*.json' -o -iname '*.xml' -o -iname '*.yml' -o -iname '*.yaml' -o -iname '*.html' -o -iname '*.css' -o -iname '*.js' -o -iname '*.sh' \
      -o -iname '*.wav' -o -iname '*.au' -o -iname '*.mp3' -o -iname '*.flac' -o -iname '*.ogg' -o -iname '*.oga' -o -iname '*.opus' -o -iname '*.m4a' -o -iname '*.aac' -o -iname '*.aif' -o -iname '*.aiff' \
    \) -print0)
    if [[ ${#FILES[@]} -eq 0 ]]; then
      die "no supported files found under '$TARGET'"
    fi
  else
    FILES=("$TARGET")
  fi
}

is_text_like() {
  local file="$1"
  local lower mime
  lower="${file,,}"

  case "$lower" in
    *.txt|*.md|*.log|*.csv|*.json|*.xml|*.yml|*.yaml|*.html|*.htm|*.css|*.js|*.sh|*.py|*.c|*.cc|*.cpp|*.h|*.hpp)
      return 0
      ;;
  esac

  mime="$(file --mime-type -b "$file" 2>/dev/null || true)"
  [[ "$mime" == text/* || "$mime" == "application/json" || "$mime" == "application/xml" || "$mime" == "application/x-sh" ]]
}

is_audio_like() {
  local file="$1"
  local lower mime
  lower="${file,,}"

  case "$lower" in
    *.wav|*.au|*.mp3|*.flac|*.ogg|*.oga|*.opus|*.m4a|*.aac|*.aif|*.aiff)
      return 0
      ;;
  esac

  mime="$(file --mime-type -b "$file" 2>/dev/null || true)"
  [[ "$mime" == audio/* ]]
}

is_steghide_like() {
  local file="$1"
  local lower mime
  lower="${file,,}"

  case "$lower" in
    *.jpg|*.jpeg|*.bmp|*.wav|*.au)
      return 0
      ;;
  esac

  mime="$(file --mime-type -b "$file" 2>/dev/null || true)"
  case "$mime" in
    image/jpeg|image/bmp|image/x-ms-bmp|audio/x-wav|audio/wav|audio/wave|audio/basic|audio/x-au)
      return 0
      ;;
  esac

  return 1
}

scan_one() {
  local file="$1"
  local base safe_base report tmp_dir collected jsteg_err tmp_out out hits flag_hits decoded_hits stegdetect_bin spectrogram
  base="$(basename "$file")"
  safe_base="$(safe_filename "$base")"
  report="$OUTPUT_DIR/stegdetect_report_${safe_base}.txt"
  tmp_dir="$(mktemp -d)"
  collected="$tmp_dir/collected.txt"
  : > "$report"
  : > "$collected"

  log() { echo -e "$1" | tee -a "$report"; }
  capture() { echo -e "$1" | tee -a "$report"; printf '%s\n' "$1" >> "$collected"; }

  log "${BOLD}############################################${RESET}"
  log "${BOLD}Scanning: $file${RESET}"
  log "${BOLD}Report: $report${RESET}"
  log "${BOLD}############################################${RESET}"

  log "\n${BOLD}--- file(1) ---${RESET}"
  out="$(file "$file" 2>&1)"
  capture "$out"

  if have strings; then
    log "\n${BOLD}--- strings (raw printable text sample) ---${RESET}"
    out="$(strings -n 6 "$file" 2>&1 | head -n 200)"
    capture "$out"
  fi

  if have exiftool; then
    log "\n${BOLD}--- exiftool (metadata) ---${RESET}"
    out="$(exiftool "$file" 2>&1)"
    capture "$out"
  fi

  if have mediainfo; then
    log "\n${BOLD}--- mediainfo (media metadata) ---${RESET}"
    if is_audio_like "$file"; then
      out="$(mediainfo "$file" 2>&1)"
      capture "$out"
    else
      log "(skipped: mediainfo section is for audio files)"
    fi
  fi

  if have stegsnow; then
    log "\n${BOLD}--- stegsnow whitespace scan ---${RESET}"
    if is_text_like "$file"; then
      out="$(stegsnow -C "$file" 2>&1 || true)"
      if [[ -n "$out" ]]; then
        capture "$out"
      else
        log "No stegsnow payload output."
      fi
    else
      log "(skipped: stegsnow targets text/whitespace files)"
    fi
  fi

  if have zbarimg; then
    log "\n${BOLD}--- QR code scan ---${RESET}"
    out="$(zbarimg --quiet "$file" 2>&1 || true)"
    if [[ -n "$out" ]]; then
      capture "$out"
    else
      log "No QR/barcode payload detected."
    fi
  fi

  stegdetect_bin="$(find_external_command stegdetect || true)"
  if [[ -z "$stegdetect_bin" ]] && have stegdetect-bin; then
    stegdetect_bin="$(command -v stegdetect-bin)"
  fi
  if [[ -n "$stegdetect_bin" ]]; then
    log "\n${BOLD}--- stegdetect JPEG scanner ---${RESET}"
    if [[ "$file" =~ \.(jpg|jpeg)$ ]]; then
      out="$("$stegdetect_bin" -tF "$file" 2>&1)"
      capture "$out"
    else
      log "(skipped: stegdetect only targets JPEG files)"
    fi
  fi

  if have zsteg; then
    log "\n${BOLD}--- zsteg ---${RESET}"
    if [[ "$file" =~ \.(png|bmp)$ ]]; then
      if [[ "$DEEP_SCAN" -eq 1 ]]; then
        out="$(zsteg -a "$file" 2>&1)"
      else
        out="$(zsteg "$file" 2>&1)"
      fi
      capture "$out"
    else
      log "(skipped: zsteg targets PNG/BMP files)"
    fi
  fi

  if have jsteg; then
    log "\n${BOLD}--- jsteg reveal ---${RESET}"
    if [[ "$file" =~ \.(jpg|jpeg)$ ]]; then
      tmp_out="$tmp_dir/jsteg.out"
      jsteg_err="$tmp_dir/jsteg.err"
      if jsteg reveal "$file" "$tmp_out" >"$jsteg_err" 2>&1; then
        if [[ -s "$tmp_out" ]]; then
          out="$(strings -n 4 "$tmp_out" 2>&1)"
          log "Revealed data as printable strings:"
          capture "$out"
        else
          log "jsteg ran but revealed no data."
        fi
      else
        out="$(cat "$jsteg_err")"
        capture "$out"
        log "(no JSteg-encoded data detected, or not a jsteg-produced file)"
      fi
    else
      log "(skipped: jsteg only targets JPEG files)"
    fi
  fi

  if have binwalk; then
    log "\n${BOLD}--- binwalk (signature scan) ---${RESET}"
    out="$(binwalk "$file" 2>&1)"
    capture "$out"
  fi

  if have sox; then
    log "\n${BOLD}--- sox spectrogram ---${RESET}"
    if is_audio_like "$file"; then
      spectrogram="$OUTPUT_DIR/stegdetect_spectrogram_${safe_base}.png"
      out="$(sox "$file" -n spectrogram -o "$spectrogram" 2>&1)"
      if [[ $? -eq 0 && -s "$spectrogram" ]]; then
        [[ -n "$out" ]] && capture "$out"
        log "Spectrogram saved to: $spectrogram"
      else
        capture "$out"
        log "Spectrogram generation failed."
      fi
    else
      log "(skipped: sox spectrogram targets audio files)"
    fi
  fi

  if have steghide; then
    if [[ -n "$STEGHIDE_PASS" ]]; then
      log "\n${BOLD}--- steghide info (passphrase supplied) ---${RESET}"
    else
      log "\n${BOLD}--- steghide info (no passphrase) ---${RESET}"
    fi
    if is_steghide_like "$file"; then
      if [[ -n "$STEGHIDE_PASS" ]]; then
        out="$(steghide info -p "$STEGHIDE_PASS" "$file" 2>&1)"
      else
        out="$(steghide info "$file" <<< "" 2>&1)"
      fi
      capture "$out"

      if [[ "$STEGHIDE_EXTRACT" -eq 1 ]]; then
        if [[ -z "$STEGHIDE_PASS" ]]; then
          log "(extraction skipped: --extract needs --passphrase or STEGDETECT_PASSPHRASE)"
        else
          tmp_out="$tmp_dir/steghide.out"
          if steghide extract -p "$STEGHIDE_PASS" -sf "$file" -xf "$tmp_out" -f >"$tmp_dir/steghide.err" 2>&1; then
            if [[ -s "$tmp_out" ]]; then
              out="$(strings -n 4 "$tmp_out" 2>&1)"
              log "Extracted steghide payload as printable strings:"
              capture "$out"

              log "\n${BOLD}--- flag pattern grep on extracted payload ---${RESET}"
              flag_hits="$(safe_grep "$FLAG_PATTERN" <<< "$out")"
              if [[ -n "$flag_hits" ]]; then
                log "${GREEN}Flag pattern matches in extracted payload:${RESET}"
                log "$flag_hits"
              else
                log "No match for: $FLAG_PATTERN"
              fi
            else
              log "steghide extracted an empty payload."
            fi
          else
            out="$(cat "$tmp_dir/steghide.err")"
            capture "$out"
            log "(extraction failed: wrong passphrase, or no embedded data)"
          fi
        fi
      fi
    else
      log "(skipped: steghide cover files must be JPEG, BMP, WAV, or AU)"
    fi
  fi

  log "\n${BOLD}--- custom pattern grep ---${RESET}"
  hits="$(strings -n 6 "$file" 2>/dev/null | safe_grep "$FLAG_PATTERN")"
  decoded_hits="$(safe_grep "$FLAG_PATTERN" < "$collected")"
  if [[ -n "$hits$decoded_hits" ]]; then
    log "${GREEN}Pattern matches found:${RESET}"
    [[ -n "$hits" ]] && log "$hits"
    [[ -n "$decoded_hits" ]] && log "$decoded_hits"
  else
    log "No match for: $FLAG_PATTERN"
  fi

  analyze_text "$file" "$collected" "$report"

  rm -rf "$tmp_dir"
  log "\n${GREEN}Report saved to: $report${RESET}"
}

check_dependencies() {
  local tools missing_tools tool reply scanner_bin
  tools=(file python3 strings exiftool zbarimg stegsnow mediainfo sox stegdetect zsteg jsteg binwalk steghide)
  missing_tools=()

  section "Dependency check"
  for tool in "${tools[@]}"; do
    if [[ "$tool" == "stegdetect" ]]; then
      scanner_bin="$(find_external_command stegdetect || true)"
      if [[ -z "$scanner_bin" ]] && have stegdetect-bin; then
        scanner_bin="$(command -v stegdetect-bin)"
      fi
      if [[ -n "$scanner_bin" ]]; then
        echo -e "  ${GREEN}[ok]${RESET} stegdetect JPEG scanner ($scanner_bin)"
      else
        echo -e "  ${YELLOW}[missing]${RESET} stegdetect JPEG scanner"
        missing_tools+=("stegdetect")
      fi
    elif have "$tool"; then
      echo -e "  ${GREEN}[ok]${RESET} $tool"
    else
      echo -e "  ${YELLOW}[missing]${RESET} $tool"
      missing_tools+=("$tool")
    fi
  done

  if [[ ${#missing_tools[@]} -eq 0 || "$PROMPT_INSTALL" -eq 0 ]]; then
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
      echo -e "\n${YELLOW}Missing tools will be skipped:${RESET} ${missing_tools[*]}"
    fi
    return 0
  fi

  echo -e "\n${YELLOW}Missing tools:${RESET} ${missing_tools[*]}"
  if [[ "$AUTO_YES" -eq 1 ]]; then
    reply="y"
  else
    read -rp "Install missing tools now? [y/N] " reply
  fi

  if [[ "$reply" =~ ^[Yy]$ ]]; then
    for tool in "${missing_tools[@]}"; do
      echo -e "\n${BOLD}Installing $tool...${RESET}"
      install_tool "$tool"
    done
  else
    echo "Skipping installs. Missing checks will be skipped during the scan."
  fi
}

main() {
  parse_args "$@"

  if [[ "$INSTALL_SELF" -eq 1 ]]; then
    install_self
    exit 0
  fi

  if [[ -z "$TARGET" ]]; then
    usage
    exit 1
  fi

  [[ -e "$TARGET" ]] || die "'$TARGET' does not exist"
  mkdir -p "$OUTPUT_DIR" || die "cannot create output directory: $OUTPUT_DIR"

  build_file_list
  check_dependencies

  local f
  for f in "${FILES[@]}"; do
    scan_one "$f"
  done
}

main "$@"
