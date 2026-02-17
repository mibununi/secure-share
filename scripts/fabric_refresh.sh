#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/mnt/c/Users/mbunc/Desktop/secure-share"
NETWORK_DIR="$HOME/fabric-samples/test-network"

CRYPTO_DIR="$REPO_ROOT/apps/api/fabric/crypto"
CONN_JSON="$REPO_ROOT/apps/api/fabric/connection-org1.json"

USER_CERT="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts"
USER_KEY="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore"
PEER_TLS_CA="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"

CC_NAME="filescc"
CC_PATH="$REPO_ROOT/chaincode/filescc"

echo "Syncing Fabric crypto into folder..."
mkdir -p "$CRYPTO_DIR"
rm -f "$CRYPTO_DIR"/*.pem

cp "$USER_CERT"/* "$CRYPTO_DIR/org1-user1-cert.pem"
cp "$USER_KEY"/*  "$CRYPTO_DIR/org1-user1-key.pem"
cp "$PEER_TLS_CA" "$CRYPTO_DIR/org1-peer-tlsca.pem"

echo "Updating peer TLS CA in connection profile..."
python3 - <<PY
import json, pathlib
conn_path = pathlib.Path(r"$CONN_JSON")
peer_ca_path = pathlib.Path(r"$PEER_TLS_CA")
data = json.loads(conn_path.read_text())
data["peers"]["peer0.org1.example.com"]["tlsCACerts"]["pem"] = peer_ca_path.read_text().strip() + "\n"
conn_path.write_text(json.dumps(data, indent=4))
print("connection-org1.json updated")
PY

echo "Deploying CCaaS chaincode..."
cd "$NETWORK_DIR"
./network.sh deployCCAAS -ccn "$CC_NAME" -ccp "$CC_PATH"

echo "Done."