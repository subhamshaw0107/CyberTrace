#!/bin/bash
# Runs INSIDE the ps26237-cli (fabric-tools) container. Called by network.sh
# and by ledger/fabric_ledger.py via `docker exec`.
set -euo pipefail

CHANNEL=provenance
CC_NAME=provenance
CC_VERSION=1.0
CC_SEQUENCE=1
ORGS=(sender auditor security backup)
POLICY="OutOf(3,'SenderOrgMSP.peer','AuditorOrgMSP.peer','SecurityOrgMSP.peer','BackupOrgMSP.peer')"
CRYPTO=/work/crypto
ORDERER_ADDR=orderer.orderer.ps26237.local:7050
ORDERER_CA=$CRYPTO/ordererOrganizations/orderer.ps26237.local/orderers/orderer.orderer.ps26237.local/tls/ca.crt

msp_of() { case $1 in sender) echo SenderOrgMSP;; auditor) echo AuditorOrgMSP;; security) echo SecurityOrgMSP;; backup) echo BackupOrgMSP;; *) echo "unknown org $1" >&2; exit 2;; esac; }
peer_addr() { echo "peer0.$1.ps26237.local:7051"; }
peer_ca() { echo "$CRYPTO/peerOrganizations/$1.ps26237.local/peers/peer0.$1.ps26237.local/tls/ca.crt"; }

use_org() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID=$(msp_of "$1")
  export CORE_PEER_ADDRESS=$(peer_addr "$1")
  export CORE_PEER_TLS_ROOTCERT_FILE=$(peer_ca "$1")
  export CORE_PEER_MSPCONFIGPATH=$CRYPTO/peerOrganizations/$1.ps26237.local/users/Admin@$1.ps26237.local/msp
}

peer_flags() {  # --peerAddresses/--tlsRootCertFiles for the given orgs
  for o in "$@"; do printf -- '--peerAddresses %s --tlsRootCertFiles %s ' "$(peer_addr "$o")" "$(peer_ca "$o")"; done
}

cmd_generate() {
  if [ ! -d "$CRYPTO/peerOrganizations" ]; then
    cryptogen generate --config=/work/crypto-config.yaml --output="$CRYPTO"
  fi
  mkdir -p /work/channel-artifacts
  FABRIC_CFG_PATH=/work configtxgen -profile ProvenanceChannel -outputBlock /work/channel-artifacts/$CHANNEL.block -channelID $CHANNEL
}

cmd_join() {
  local oc=$CRYPTO/ordererOrganizations/orderer.ps26237.local/orderers/orderer.orderer.ps26237.local/tls
  for i in $(seq 1 20); do
    if osnadmin channel join --channelID $CHANNEL --config-block /work/channel-artifacts/$CHANNEL.block \
        -o orderer.orderer.ps26237.local:7053 --ca-file "$oc/ca.crt" --client-cert "$oc/server.crt" --client-key "$oc/server.key"; then break; fi
    sleep 2
  done
  for o in "${ORGS[@]}"; do
    use_org "$o"
    for i in $(seq 1 20); do peer channel join -b /work/channel-artifacts/$CHANNEL.block && break; sleep 2; done
  done
}

cmd_install() {
  mkdir -p /work/cc-packages
  : > /work/.env
  for o in "${ORGS[@]}"; do
    local d; d=$(mktemp -d)
    printf '{"address":"cc.%s.ps26237.local:9999","dial_timeout":"10s","tls_required":false}' "$o" > "$d/connection.json"
    printf '{"type":"ccaas","label":"%s_%s"}' "$CC_NAME" "$o" > "$d/metadata.json"
    # Deterministic archives: the package ID is a hash of these bytes, so timestamps
    # and ownership must be fixed or re-running `install` would invent a new package ID
    # that no longer matches the chaincode definition committed on the channel.
    tar -C "$d" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - connection.json | gzip -n > "$d/code.tar.gz"
    tar -C "$d" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - metadata.json code.tar.gz | gzip -n > /work/cc-packages/$CC_NAME-$o.tar.gz
    use_org "$o"
    peer lifecycle chaincode install /work/cc-packages/$CC_NAME-$o.tar.gz || true  # already installed is fine
    local id; id=$(peer lifecycle chaincode calculatepackageid /work/cc-packages/$CC_NAME-$o.tar.gz)
    echo "CCID_${o^^}=$id" >> /work/.env
  done
  cat /work/.env
}

cmd_approve_commit() {
  set -a; . /work/.env; set +a
  use_org sender
  if peer lifecycle chaincode querycommitted -C $CHANNEL -n $CC_NAME 2>/dev/null | grep -q "Version: $CC_VERSION, Sequence: $CC_SEQUENCE"; then
    echo "chaincode $CC_NAME v$CC_VERSION seq $CC_SEQUENCE already committed on $CHANNEL -- nothing to do"
    return 0
  fi
  for o in "${ORGS[@]}"; do
    use_org "$o"
    local var="CCID_${o^^}"
    peer lifecycle chaincode approveformyorg -o $ORDERER_ADDR --tls --cafile "$ORDERER_CA" -C $CHANNEL -n $CC_NAME \
      --version $CC_VERSION --sequence $CC_SEQUENCE --package-id "${!var}" --signature-policy "$POLICY" --waitForEvent
  done
  use_org sender
  peer lifecycle chaincode checkcommitreadiness -C $CHANNEL -n $CC_NAME --version $CC_VERSION --sequence $CC_SEQUENCE --signature-policy "$POLICY"
  peer lifecycle chaincode commit -o $ORDERER_ADDR --tls --cafile "$ORDERER_CA" -C $CHANNEL -n $CC_NAME \
    --version $CC_VERSION --sequence $CC_SEQUENCE --signature-policy "$POLICY" $(peer_flags "${ORGS[@]}")
  peer lifecycle chaincode querycommitted -C $CHANNEL -n $CC_NAME
}

# query <org> : reads {"Args":[...]} ctor JSON on stdin, queries that org's peer only.
cmd_query() {
  use_org "$1"
  local ctor; ctor=$(cat)
  peer chaincode query -C $CHANNEL -n $CC_NAME -c "$ctor"
}

# invoke <submitter-org> <endorser-org,...> : ctor JSON on stdin.
cmd_invoke() {
  use_org "$1"
  IFS=, read -r -a endorsers <<< "$2"
  local ctor; ctor=$(cat)
  peer chaincode invoke -o $ORDERER_ADDR --tls --cafile "$ORDERER_CA" -C $CHANNEL -n $CC_NAME \
    $(peer_flags "${endorsers[@]}") -c "$ctor" --waitForEvent --waitForEventTimeout 60s
}

case "${1:-}" in
  generate) cmd_generate ;;
  join) cmd_join ;;
  install) cmd_install ;;
  approve-commit) cmd_approve_commit ;;
  query) cmd_query "$2" ;;
  invoke) cmd_invoke "$2" "$3" ;;
  *) echo "usage: cli.sh generate|join|install|approve-commit|query <org>|invoke <org> <endorsers>" >&2; exit 2 ;;
esac
