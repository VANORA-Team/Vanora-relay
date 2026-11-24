#!/usr/bin/env bash
# Isolated production-path relay test. Run as root inside a Linux namespace-
# capable host (WSL2 Debian works). Creates four bridges and three network
# namespaces, disables IP forwarding so direct peer-to-peer paths cannot work,
# then runs the harness.
#
#   ./run.sh /tmp/relaye2e-bin
#
# /tmp/relaye2e-bin must contain Linux amd64 binaries: relay and relaye2e.
set -euo pipefail

BIN_DIR=${1:-/tmp/relaye2e-bin}
RELAY_BIN=$BIN_DIR/relay
HARNESS_BIN=$BIN_DIR/relaye2e

if [ "$(id -u)" != 0 ]; then
  echo "run as root (namespaces and bridges are required)" >&2
  exit 1
fi
for f in "$RELAY_BIN" "$HARNESS_BIN"; do
  if [ ! -x "$f" ]; then
    echo "missing executable: $f" >&2
    exit 1
  fi
done
command -v ip >/dev/null || { echo "iproute2 is required" >&2; exit 1; }

DIR=$(mktemp -d /tmp/vanora-relaye2e.XXXXXXXX)
trap 'rmdir -- "$DIR"' EXIT
unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private \
  bash -s -- "$DIR" "$RELAY_BIN" "$HARNESS_BIN" <<'LAB'
set -euo pipefail
DIR=$1
mount -t tmpfs -o mode=0700 tmpfs "$DIR"
install -m 0700 -- "$2" "$DIR/relay"
install -m 0700 -- "$3" "$DIR/relaye2e"
mount -t tmpfs -o mode=0755 tmpfs /run
ip link set lo up

sysctl -qw net.ipv4.ip_forward=0
sysctl -qw net.ipv4.conf.all.rp_filter=0

bridge() { # name address
  ip link add "$1" type bridge
  ip addr add "$2" dev "$1"
  ip link set "$1" up
}

netns_link() { # ns bridge veth addr gateway [extra-route]
  local ns=$1 br=$2 veth=$3
  ip netns add "$ns"
  ip link add "$veth" type veth peer name "$veth-ns"
  ip link set "$veth" master "$br"
  ip link set "$veth" up
  ip link set "$veth-ns" netns "$ns"
  ip -n "$ns" addr add "$4" dev "$veth-ns"
  ip -n "$ns" link set "$veth-ns" up
  ip -n "$ns" link set lo up
  ip -n "$ns" route add default via "$5"
  if [ $# -ge 6 ]; then
    ip -n "$ns" route add "$6" via "$5"
  fi
}

bridge br-d 172.31.61.1/24
bridge br-m 172.31.62.1/24
bridge br-p 172.31.60.1/24
bridge br-e 8.8.8.1/24

netns_link vanora-desktop br-d vd 172.31.61.2/24 172.31.61.1 172.31.60.0/24
netns_link vanora-mobile br-m vm 172.31.62.2/24 172.31.62.1 172.31.60.0/24
netns_link vanora-echo br-e ve 8.8.8.8/24 8.8.8.1

echo "network ready: relay=172.31.60.1 clients=172.31.61.2/172.31.62.2 echo=8.8.8.8"
"$DIR/relaye2e" \
  -role parent \
  -dir "$DIR" \
  -bin "$DIR/relaye2e" \
  -relay "$DIR/relay" \
  -issuer https://issuer.example
LAB
