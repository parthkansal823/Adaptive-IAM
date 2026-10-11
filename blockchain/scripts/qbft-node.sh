#!/bin/sh
set -eu
test -s /node-key/key
test -s /network/genesis.json
cp /network/static-nodes.json /var/lib/besu/static-nodes.json
cp /network/permissions_config.toml /tmp/permissions_config.toml
for alias in qbft1 qbft2 qbft3 qbft4; do
  case "$alias" in
    qbft1) node_ip="$QBFT_PREFIX.10" ;;
    qbft2) node_ip="$QBFT_PREFIX.11" ;;
    qbft3) node_ip="$QBFT_PREFIX.12" ;;
    qbft4) node_ip="$QBFT_PREFIX.13" ;;
  esac
  test -n "$node_ip"
  sed -i "s/@$alias:/@$node_ip:/g" /var/lib/besu/static-nodes.json /tmp/permissions_config.toml
done
own_ip="$NODE_IPV4"
exec /opt/besu/bin/besu \
  --data-path=/var/lib/besu --node-private-key-file=/node-key/key \
  --genesis-file=/network/genesis.json --sync-mode=FULL --data-storage-format=BONSAI \
  --discovery-enabled=false --p2p-interface=0.0.0.0 --p2p-host="$own_ip" \
  --rpc-http-enabled=true --rpc-http-host=0.0.0.0 --rpc-http-port=8545 \
  --rpc-http-api=ETH,NET,QBFT --host-allowlist="$NODE_ALIAS,localhost,127.0.0.1" \
  --permissions-nodes-config-file-enabled=true --permissions-nodes-config-file=/tmp/permissions_config.toml \
  --min-gas-price=0 --logging=WARN
