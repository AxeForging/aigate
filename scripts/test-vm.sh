#!/usr/bin/env bash
# Run aigate's test suite inside a throwaway VM of a given Linux distro.
#
#   scripts/test-vm.sh ubuntu-24.04      # one distro
#   scripts/test-vm.sh all               # every distro, one VM at a time
#
# Uses official cloud images (checksum-verified, cached in
# ~/.cache/aigate-vm), qemu with KVM and user-mode networking (no root, no
# libvirt). Each VM gets 2 vCPU / 2 GB, runs the tests as an unprivileged
# user, and is deleted afterwards. Logs: ~/.cache/aigate-vm/results/.
set -euo pipefail

DISTROS=(fedora-43 fedora-44 ubuntu-22.04 ubuntu-24.04 debian-12 debian-13 arch rocky-9)
REPO=$(cd "$(dirname "$0")/.." && pwd)
CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/aigate-vm
RESULTS=$CACHE/results

die() { echo "test-vm: $*" >&2; exit 1; }

usage() {
	echo "usage: $0 DISTRO|all"
	echo "distros: ${DISTROS[*]}"
	exit 2
}

# image_info DISTRO -> prints "IMAGE_URL SUMS_URL"
image_info() {
	case $1 in
	ubuntu-22.04) echo "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS" ;;
	ubuntu-24.04) echo "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img https://cloud-images.ubuntu.com/noble/current/SHA256SUMS" ;;
	debian-12) echo "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2 https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS" ;;
	debian-13) echo "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2 https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS" ;;
	arch) echo "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2 https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256" ;;
	rocky-9) echo "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2 https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM" ;;
	fedora-*)
		# Fedora file names carry a build number; read it from the release dir.
		local v=${1#fedora-} base listing img sums
		base="https://dl.fedoraproject.org/pub/fedora/linux/releases/$v/Cloud/x86_64/images"
		listing=$(curl -fsSL --proto '=https' "$base/") || die "can't list $base (is Fedora $v released?)"
		img=$(grep -oE "Fedora-Cloud-Base-Generic-$v-[0-9.]+\.x86_64\.qcow2" <<<"$listing" | sort -u | tail -1)
		sums=$(grep -oE "Fedora-Cloud-$v-[0-9.]+-x86_64-CHECKSUM" <<<"$listing" | sort -u | tail -1)
		[[ -n $img && -n $sums ]] || die "no Fedora $v cloud image found in $base"
		echo "$base/$img $base/$sums"
		;;
	*) die "unknown distro '$1' (known: ${DISTROS[*]})" ;;
	esac
}

# packages DISTRO -> sandbox tools + what the tests use
packages() {
	case $1 in
	arch) echo "bubblewrap slirp4netns acl git python iptables-nft" ;;
	# Fedora desktops ship the nf_tables iptables; the cloud image only has legacy.
	fedora-*) echo "bubblewrap slirp4netns acl git python3 iptables-nft" ;;
	*) echo "bubblewrap slirp4netns acl git python3 iptables" ;;
	esac
}

# fetch_image DISTRO -> prints the cached, verified image path
fetch_image() {
	local url sums file sumfile expected actual algo
	read -r url sums < <(image_info "$1")
	file=$CACHE/images/$1-$(basename "$url")
	[[ -f $file ]] && { echo "$file"; return; }
	mkdir -p "$CACHE/images"
	sumfile=$(mktemp)
	curl -fsSL --proto '=https' -o "$sumfile" "$sums" || die "can't download checksums $sums"
	expected=$(grep -F "$(basename "$url")" "$sumfile" | grep -oE '[0-9a-f]{128}|[0-9a-f]{64}' | head -1)
	rm -f "$sumfile"
	[[ -n $expected ]] || die "no checksum for $(basename "$url") in $sums"
	algo=sha256sum
	[[ ${#expected} -eq 128 ]] && algo=sha512sum
	echo "test-vm: downloading $url" >&2
	curl -fL --proto '=https' --progress-bar -o "$file.part" "$url" || die "download failed: $url"
	actual=$($algo "$file.part" | cut -d' ' -f1)
	if [[ $actual != "$expected" ]]; then
		rm -f "$file.part"
		die "checksum mismatch for $url"
	fi
	mv "$file.part" "$file"
	echo "$file"
}

# build_payload DIR: aigate + test binaries laid out like the repo
build_payload() {
	local out=$1
	mkdir -p "$out/integration" "$out/services"
	(cd "$REPO" &&
		CGO_ENABLED=0 go build -o "$out/aigate" . &&
		CGO_ENABLED=0 go test -c -o "$out/integration/integration.test" ./integration &&
		CGO_ENABLED=0 go test -c -o "$out/services/services.test" ./services &&
		cp install.sh "$out/install.sh")
}

free_port() {
	python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# The script that runs inside the VM, as the unprivileged test user.
read -r -d '' GUEST_SCRIPT <<'GUEST' || true
set -u
cd ~/payload
echo "== host: $(. /etc/os-release; echo "$PRETTY_NAME") | kernel $(uname -r) | $(bwrap --version 2>&1)"
echo "== apparmor_restrict_unprivileged_userns=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = "1" ]; then
	if ./aigate doctor >/tmp/doctor.txt 2>&1 || ! grep -q "AppArmor is blocking" /tmp/doctor.txt; then
		cat /tmp/doctor.txt; echo "== FAIL: doctor did not explain the AppArmor block"; exit 1
	fi
	echo "== doctor explained the AppArmor block; applying the printed fix"
	sudo tee /etc/apparmor.d/bwrap >/dev/null <<EOF
abi <abi/4.0>,
include <tunables/global>
profile bwrap $(command -v bwrap) flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
	sudo systemctl reload apparmor
fi
./aigate doctor | grep -E 'Verdict'
export AIGATE_TEST_BIN=$HOME/payload/aigate
rc=0
(cd services && ./services.test -test.count=1) || rc=1
(cd integration && ./integration.test -test.count=1) || rc=1
exit $rc
GUEST

run_one() {
	local distro=$1 img work port rc=0 key ssh_opts pkgs
	img=$(fetch_image "$distro")
	work=$(mktemp -d)
	mkdir -p "$RESULTS"
	local log=$RESULTS/$distro.log
	# shellcheck disable=SC2064
	trap "[[ -f $work/qemu.pid ]] && kill \$(cat $work/qemu.pid) 2>/dev/null; rm -rf $work" RETURN

	build_payload "$work/payload" || die "build failed"
	ssh-keygen -q -t ed25519 -N '' -f "$work/key"
	key=$(cat "$work/key.pub")
	pkgs=$(packages "$distro")
	cat >"$work/user-data" <<EOF
#cloud-config
users:
  - name: tester
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys: [$key]
package_update: true
packages: [${pkgs// /, }]
EOF
	printf 'instance-id: aigate-%s\nlocal-hostname: aigate-test\n' "$distro" >"$work/meta-data"
	genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/user-data" "$work/meta-data"
	qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$work/disk.qcow2" 20G
	port=$(free_port)

	qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -display none \
		-serial "file:$work/console.log" \
		-drive "file=$work/disk.qcow2,if=virtio" \
		-drive "file=$work/seed.iso,if=virtio,format=raw,readonly=on" \
		-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0 \
		-daemonize -pidfile "$work/qemu.pid"

	ssh_opts=(-i "$work/key" -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR)
	echo "test-vm: $distro booting (port $port)…" >&2
	for _ in $(seq 1 90); do
		ssh "${ssh_opts[@]}" tester@127.0.0.1 true 2>/dev/null && break
		sleep 4
	done
	ssh "${ssh_opts[@]}" tester@127.0.0.1 true || { cp "$work/console.log" "$log"; die "$distro: VM never became reachable (console in $log)"; }
	# cloud-init exits 2 for recoverable warnings; packages are what matter.
	ssh "${ssh_opts[@]}" tester@127.0.0.1 'sudo cloud-init status --wait >/dev/null; command -v bwrap >/dev/null' ||
		{ echo "$distro: packages missing after cloud-init" >"$log"; die "$distro: bwrap not installed"; }
	scp -q -r -P "$port" -i "$work/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		"$work/payload" tester@127.0.0.1:
	ssh "${ssh_opts[@]}" tester@127.0.0.1 "bash -s" <<<"$GUEST_SCRIPT" >"$log" 2>&1 || rc=$?
	if ((rc == 0)); then echo "PASS $distro  ($(head -1 "$log" | cut -c4-))"; else echo "FAIL $distro  (log: $log)"; fi
	return "$rc"
}

[[ $# -eq 1 ]] || usage
for tool in qemu-system-x86_64 qemu-img genisoimage ssh scp ssh-keygen curl go python3; do
	command -v "$tool" >/dev/null || die "missing $tool"
done
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm not accessible (add yourself to the kvm group)"

if [[ $1 == all ]]; then
	failed=0
	for d in "${DISTROS[@]}"; do run_one "$d" || failed=1; done
	exit $failed
fi
run_one "$1"
