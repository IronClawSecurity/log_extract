#!/bin/sh
# log_extract POSIX launcher — invoked by the Linux/macOS BadUSB payloads
# from the Flipper SD root. Picks the right pre-built binary based on
# `uname -s` and writes the archive back to the Flipper drive.
set -eu

DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

case "$(uname -s)" in
    Linux)  BIN="$DIR/log_extract_linux" ;;
    Darwin) BIN="$DIR/log_extract_macos" ;;
    *)      echo "[log_extract] unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac

if [ ! -x "$BIN" ]; then
    echo "[log_extract] missing or non-executable binary: $BIN" >&2
    exit 2
fi

echo "[log_extract] running $BIN"
"$BIN" -a -o "$DIR/output"
RC=$?
echo "[log_extract] exit=$RC archive in $DIR/output"
sleep 5
exit $RC
