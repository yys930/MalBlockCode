#!/usr/bin/env bash
set -euo pipefail

NFT_BIN="${NFT_BIN:-sudo nft}"
NFT_TABLE="${NFT_TABLE:-inet}"
NFT_FAMILY_TABLE="${NFT_FAMILY_TABLE:-filter}"
NFT_BLOCK_SET="${NFT_SET:-blocklist_v4}"
NFT_RATE_LIMIT_SET="${NFT_RATE_LIMIT_SET:-ratelimit_v4}"
NFT_WATCH_SET="${NFT_WATCH_SET:-watchlist_v4}"

RATE_LIMIT="${NFT_RATE_LIMIT:-30/second}"
RATE_BURST="${NFT_RATE_BURST:-60 packets}"
WATCH_LOG_PREFIX="${NFT_WATCH_LOG_PREFIX:-MB_WATCH}"
WATCH_LOG_RATE="${NFT_WATCH_LOG_RATE:-5/second}"
WATCH_LOG_BURST="${NFT_WATCH_LOG_BURST:-10 packets}"

nft_cmd() {
  ${NFT_BIN} "$@"
}

has_table() {
  nft_cmd list table "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" >/dev/null 2>&1
}

has_chain() {
  local chain_name="$1"
  nft_cmd list chain "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" "${chain_name}" >/dev/null 2>&1
}

has_set() {
  local set_name="$1"
  nft_cmd list set "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" "${set_name}" >/dev/null 2>&1
}

ensure_table() {
  if ! has_table; then
    nft_cmd add table "${NFT_TABLE}" "${NFT_FAMILY_TABLE}"
  fi
}

ensure_chain() {
  local chain_name="$1"
  local hook_name="$2"
  if ! has_chain "${chain_name}"; then
    nft_cmd add chain "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" "${chain_name}" "{ type filter hook ${hook_name} priority 0 ; policy accept ; }"
  fi
}

ensure_set() {
  local set_name="$1"
  if ! has_set "${set_name}"; then
    nft_cmd add set "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" "${set_name}" "{ type ipv4_addr; flags interval,timeout; }"
  fi
}

ensure_rule() {
  local chain_name="$1"
  local rule_expr="$2"
  local chain_dump
  chain_dump="$(nft_cmd -a list chain "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" "${chain_name}" 2>/dev/null || true)"
  if ! grep -Fq "${rule_expr}" <<<"${chain_dump}"; then
    nft_cmd add rule "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" "${chain_name}" ${rule_expr}
  fi
}

main() {
  ensure_table

  ensure_chain "input" "input"
  ensure_chain "forward" "forward"

  ensure_set "${NFT_BLOCK_SET}"
  ensure_set "${NFT_RATE_LIMIT_SET}"
  ensure_set "${NFT_WATCH_SET}"

  ensure_rule "input" "ip saddr @${NFT_BLOCK_SET} counter drop"
  ensure_rule "forward" "ip saddr @${NFT_BLOCK_SET} counter drop"

  ensure_rule "input" "ip saddr @${NFT_RATE_LIMIT_SET} limit rate ${RATE_LIMIT} burst ${RATE_BURST} counter accept"
  ensure_rule "input" "ip saddr @${NFT_RATE_LIMIT_SET} counter drop"
  ensure_rule "forward" "ip saddr @${NFT_RATE_LIMIT_SET} limit rate ${RATE_LIMIT} burst ${RATE_BURST} counter accept"
  ensure_rule "forward" "ip saddr @${NFT_RATE_LIMIT_SET} counter drop"

  ensure_rule "input" "ip saddr @${NFT_WATCH_SET} limit rate ${WATCH_LOG_RATE} burst ${WATCH_LOG_BURST} counter log prefix ${WATCH_LOG_PREFIX}"
  ensure_rule "forward" "ip saddr @${NFT_WATCH_SET} limit rate ${WATCH_LOG_RATE} burst ${WATCH_LOG_BURST} counter log prefix ${WATCH_LOG_PREFIX}"

  echo "Initialized nftables objects:"
  echo "  table: ${NFT_TABLE} ${NFT_FAMILY_TABLE}"
  echo "  drop set: ${NFT_BLOCK_SET}"
  echo "  rate-limit set: ${NFT_RATE_LIMIT_SET}"
  echo "  watch set: ${NFT_WATCH_SET}"
  echo
  nft_cmd list table "${NFT_TABLE}" "${NFT_FAMILY_TABLE}"
}

main "$@"
