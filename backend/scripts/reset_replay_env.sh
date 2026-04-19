#!/usr/bin/env bash
set -euo pipefail

NETNS_NAME="${NETNS_NAME:-mbreplay}"
HOST_IF="${HOST_IF:-veth-mb-host}"

if ip link show "$HOST_IF" >/dev/null 2>&1; then
  sudo ip link delete "$HOST_IF"
  echo "Deleted host interface: $HOST_IF"
else
  echo "Host interface not found: $HOST_IF"
fi

if sudo ip netns list | awk '{print $1}' | grep -Fxq "$NETNS_NAME"; then
  sudo ip netns delete "$NETNS_NAME"
  echo "Deleted netns: $NETNS_NAME"
else
  echo "Netns not found: $NETNS_NAME"
fi
