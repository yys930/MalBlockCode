#!/usr/bin/env bash
set -euo pipefail

NETNS_NAME="${NETNS_NAME:-mbreplay}"
HOST_IF="${HOST_IF:-veth-mb-host}"
REPLAY_IF="${REPLAY_IF:-veth-mb-replay}"
HOST_MTU="${HOST_MTU:-32000}"
REPLAY_MTU="${REPLAY_MTU:-32000}"

has_netns() {
  sudo ip netns list | awk '{print $1}' | grep -Fxq "$NETNS_NAME"
}

has_host_if() {
  ip link show "$HOST_IF" >/dev/null 2>&1
}

has_replay_if_in_netns() {
  sudo ip netns exec "$NETNS_NAME" ip link show "$REPLAY_IF" >/dev/null 2>&1
}

disable_host_offloads() {
  sudo ethtool -K "$HOST_IF" gro off gso off tso off lro off >/dev/null
}

disable_replay_offloads() {
  sudo ip netns exec "$NETNS_NAME" ethtool -K "$REPLAY_IF" gro off gso off tso off lro off >/dev/null
}

main() {
  if ! has_netns; then
    sudo ip netns add "$NETNS_NAME"
  fi

  if ! has_host_if; then
    sudo ip link add "$HOST_IF" type veth peer name "$REPLAY_IF"
  fi

  if has_host_if && ! has_replay_if_in_netns; then
    sudo ip link set "$REPLAY_IF" netns "$NETNS_NAME"
  fi

  sudo ip link set "$HOST_IF" mtu "$HOST_MTU"
  sudo ip link set "$HOST_IF" up
  sudo ip link set "$HOST_IF" promisc on
  disable_host_offloads

  sudo ip netns exec "$NETNS_NAME" ip link set lo up
  sudo ip netns exec "$NETNS_NAME" ip link set "$REPLAY_IF" mtu "$REPLAY_MTU"
  sudo ip netns exec "$NETNS_NAME" ip link set "$REPLAY_IF" up
  sudo ip netns exec "$NETNS_NAME" ip link set "$REPLAY_IF" promisc on
  disable_replay_offloads

  echo "Replay environment ready."
  echo "  netns: $NETNS_NAME"
  echo "  suricata interface: $HOST_IF"
  echo "  replay interface: $REPLAY_IF"
  echo "  host mtu: $HOST_MTU"
  echo "  replay mtu: $REPLAY_MTU"
  echo "  offloads: gro/gso/tso/lro disabled on both ends"
  echo
  ip -brief link show "$HOST_IF"
  sudo ip netns exec "$NETNS_NAME" ip -brief link show "$REPLAY_IF"
}

main "$@"
