#!/bin/bash

set -eux

FORGE_PATH="/root/.foundry/bin"

[[ ":$PATH:" != *${FORGE_PATH}* ]] && PATH="${FORGE_PATH}:${PATH}"

lib_addr=`forge create --json --rpc-url http://suave-mevm:8545 --private-key 91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12 lib/rave/src/X509Verifier.sol:X509Verifier | jq .deployedTo | tr -d '"'`

forge build --names --force --libraries lib/rave/src/X509Verifier.sol:X509Verifier:${lib_addr}

go run examples/tee-kettle/main.go
