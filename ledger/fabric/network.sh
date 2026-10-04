#!/bin/bash
# PS 26237 Hyperledger Fabric provenance network.
#   ./network.sh up                 generate identities, start orderer + 4 peers, create channel, deploy chaincode
#   ./network.sh down               stop and delete containers, volumes and generated identities
#   ./network.sh rogue <recipient>  restart SecurityOrg's chaincode in compromised mode (tests only)
#   ./network.sh honest             restart SecurityOrg's chaincode in honest mode
set -euo pipefail
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: don't rewrite container paths

cli() { docker exec -i ps26237-cli bash /work/scripts/cli.sh "$@"; }
CC_SERVICES="cc.sender.ps26237.local cc.auditor.ps26237.local cc.security.ps26237.local cc.backup.ps26237.local"

case "${1:-}" in
  up)
    docker build -q -t ps26237/provenance-cc:latest chaincode/provenance
    docker compose up -d cli
    cli generate
    docker compose up -d orderer.orderer.ps26237.local peer0.sender.ps26237.local peer0.auditor.ps26237.local \
      peer0.security.ps26237.local peer0.backup.ps26237.local
    cli join
    cli install
    ROGUE_FRAME= docker compose up -d $CC_SERVICES
    cli approve-commit
    echo "Network up: channel 'provenance', chaincode 'provenance', endorsement OutOf(3, 4 orgs)."
    ;;
  down)
    docker compose down -v --remove-orphans
    rm -rf crypto channel-artifacts cc-packages .env
    ;;
  rogue)
    ROGUE_FRAME="${2:?recipient to frame}" docker compose up -d --force-recreate cc.security.ps26237.local
    ;;
  honest)
    ROGUE_FRAME= docker compose up -d --force-recreate cc.security.ps26237.local
    ;;
  *)
    sed -n '2,6p' "$0"; exit 2 ;;
esac
