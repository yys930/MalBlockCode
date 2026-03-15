#!/usr/bin/env bash
set -euo pipefail

NFT_BIN="${NFT_BIN:-sudo nft}"
NFT_TABLE="${NFT_TABLE:-inet}"
NFT_FAMILY_TABLE="${NFT_FAMILY_TABLE:-filter}"

nft_cmd() {
  ${NFT_BIN} "$@"
}

main() {
  if nft_cmd list table "${NFT_TABLE}" "${NFT_FAMILY_TABLE}" >/dev/null 2>&1; then
    nft_cmd delete table "${NFT_TABLE}" "${NFT_FAMILY_TABLE}"
    echo "Deleted nftables table: ${NFT_TABLE} ${NFT_FAMILY_TABLE}"
  else
    echo "Table not found, nothing to reset: ${NFT_TABLE} ${NFT_FAMILY_TABLE}"
  fi
}

main "$@"
