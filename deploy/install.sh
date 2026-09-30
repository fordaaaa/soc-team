#!/bin/sh
# socteam installer for a Raspberry Pi / any aarch64 (or x86_64) Linux box.
# Run as root from an extracted release tarball (or the repo root after
# `cargo build --release`):  sudo ./deploy/install.sh
set -eu

BIN_DIR="${1:-/usr/local/bin}"
ETC_DIR=/etc/socteam
LIB_DIR=/var/lib/socteam/events
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

# Binaries: from this directory, else from the repo's target/release.
if [ -x "$HERE/socteam-sensor" ]; then
  SRC="$HERE"
elif [ -x "$HERE/../target/release/socteam-sensor" ]; then
  SRC="$HERE/../target/release"
else
  echo "no binaries found in $HERE or $HERE/../target/release"; exit 1
fi

install -m 0755 "$SRC/socteam-sensor" "$SRC/socteam" "$SRC/socteam-console" "$BIN_DIR/"

# Config: never overwrite an existing one.
mkdir -p "$ETC_DIR"
if [ ! -f "$ETC_DIR/socteam.toml" ]; then
  install -m 0644 "$SRC/socteam.toml.example" "$ETC_DIR/socteam.toml"
  echo "wrote $ETC_DIR/socteam.toml — edit it (iface, ntfy) before starting"
fi

mkdir -p "$LIB_DIR"

# Units.
install -m 0644 "$HERE/socteam-sensor.service" "$HERE/socteam-console.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable socteam-sensor.service socteam-console.service

echo
echo "next:"
echo "  1. edit $ETC_DIR/socteam.toml  (iface = ..., [alert] ntfy_url/topic)"
echo "  2. systemctl start socteam-sensor socteam-console"
echo "  3. journalctl -u socteam-sensor -f   # watch for ALERT lines"
