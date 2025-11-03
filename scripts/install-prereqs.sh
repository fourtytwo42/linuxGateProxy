#!/usr/bin/env bash
set -euo pipefail

if ! command -v sudo >/dev/null 2>&1; then
  echo "This script requires sudo to install packages." >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y samba cloudflared
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y samba cloudflared
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y samba cloudflared
else
  echo "Unsupported package manager. Install 'samba' and 'cloudflared' manually." >&2
  exit 1
fi

echo "Prerequisites installation complete."
