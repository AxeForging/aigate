#!/bin/sh
set -eu
REPO="${AIGATE_REPO:-AxeForging/aigate}"; VERSION="${AIGATE_VERSION:-latest}"; INSTALL_DIR="${AIGATE_INSTALL_DIR:-${HOME:?HOME required}/.local/bin}"
die(){ printf 'aigate installer: %s\n' "$*" >&2; exit 1; }
case "$(uname -s)" in Linux) os=linux;; Darwin) os=darwin;; *) die "unsupported OS";; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die "unsupported architecture";; esac
if [ "$VERSION" = latest ]; then VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | awk -F/ '{print $NF}')"; fi
asset="aigate-${os}-${arch}.tar.gz"; binary="aigate-${os}-${arch}"; base="https://github.com/$REPO/releases/download/$VERSION"; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/$asset" -o "$tmp/$asset"; curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
expected="$(awk -v a="$asset" '$2==a||$2=="*"a{print $1;exit}' "$tmp/checksums.txt")"; [ -n "$expected" ] || die "checksum not found"
actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"; [ "$actual" = "$expected" ] || die "checksum verification failed"
tar -xzf "$tmp/$asset" -C "$tmp"; [ -f "$tmp/$binary" ] || die "archive missing binary"; mkdir -p "$INSTALL_DIR"; install -m 0755 "$tmp/$binary" "$INSTALL_DIR/aigate"
