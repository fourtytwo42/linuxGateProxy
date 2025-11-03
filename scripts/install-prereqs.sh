#!/usr/bin/env bash
set -euo pipefail

if ! command -v sudo >/dev/null 2>&1; then
  echo "This script requires sudo privileges." >&2
  exit 1
fi

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64)
    CF_ARCH="amd64"
    ;;
  aarch64|arm64)
    CF_ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: ${ARCH}. Install cloudflared manually." >&2
    CF_ARCH=""
    ;;
 esac

install_cloudflared_binary() {
  if [[ -z "${CF_ARCH}" ]]; then
    return 1
  fi
  echo "Installing cloudflared from GitHub release..."
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT
  url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
  curl -fsSL "${url}" -o "${tmpdir}/cloudflared"
  sudo install -m 755 "${tmpdir}/cloudflared" /usr/local/bin/cloudflared
  echo "cloudflared installed to /usr/local/bin/cloudflared"
}

install_with_apt() {
  sudo apt-get update
  sudo apt-get install -y samba || true
  if ! sudo apt-get install -y cloudflared; then
    install_cloudflared_binary || {
      echo "Failed to install cloudflared via apt or direct download." >&2
      return 1
    }
  fi
  return 0
}

install_with_dnf() {
  sudo dnf install -y samba || true
  if sudo dnf install -y cloudflared; then
    return 0
  fi
  install_cloudflared_binary
}

install_with_yum() {
  sudo yum install -y samba || true
  if sudo yum install -y cloudflared; then
    return 0
  fi
  install_cloudflared_binary
}

if command -v apt-get >/dev/null 2>&1; then
  install_with_apt
elif command -v dnf >/dev/null 2>&1; then
  install_with_dnf
elif command -v yum >/dev/null 2>&1; then
  install_with_yum
else
  echo "Unsupported package manager. Install 'samba' and 'cloudflared' manually." >&2
  exit 1
fi

echo "Prerequisites installation complete."
