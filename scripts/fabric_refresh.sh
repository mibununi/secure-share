#!/usr/bin/env bash
set -euo pipefail

# Config
REPO_ROOT="/mnt/c/Users/mbunc/Desktop/secure-share"
NETWORK_DIR="$HOME/fabric-samples/test-network"

CRYPTO_DIR="$REPO_ROOT/apps/api/fabric/crypto"
CONN_JSON="$REPO_ROOT/apps/api/fabric/connection-org1.json"

CC_NAME="filescc"
CC_PATH="$REPO_ROOT/chaincode/filescc"
CHANNEL_NAME="mychannel"

# Org/peer paths in fabric-samples test-network
USER_CERT_DIR="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts"
USER_KEY_DIR="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore"
PEER_TLS_CA_FILE="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"

# CA TLS cert
CA_TLS_CERT_FILE="$NETWORK_DIR/organizations/fabric-ca/org1/tls-cert.pem"

# CCaaS containers created by test-network scripts
CCAAS_CONTAINERS=(
  "peer0org1_${CC_NAME}_ccaas"
  "peer0org2_${CC_NAME}_ccaas"
)

# Helpers
die() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [[ -f "$1" ]] || die "Missing file: $1"; }
require_dir() { [[ -d "$1" ]] || die "Missing directory: $1"; }

# Environment checks

# Check that the environment is  a Linux/WSL-like with access to fabric-samples paths
[[ -d "$NETWORK_DIR" ]] || die "NETWORK_DIR not found: $NETWORK_DIR. Run this script in WSL where fabric-samples exists."

command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found in PATH"
[[ -x "$NETWORK_DIR/network.sh" ]] || die "network.sh not found or not executable at: $NETWORK_DIR/network.sh"

# Network down
echo "Bringing Fabric network down..."
cd "$NETWORK_DIR"
./network.sh down || true

# Remove conflicting CCaaS containers
echo "Cleaning up previous CCaaS containers..."
for c in "${CCAAS_CONTAINERS[@]}"; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
    docker rm -f "$c" >/dev/null
    echo "Removed container: $c"
  fi
done

# Remove stopped containers left around
docker container prune -f >/dev/null || true

# Network up + channel
echo "Bringing Fabric network up and creating channel..."
./network.sh up createChannel -ca -c "$CHANNEL_NAME"

# Deploy CCaaS chaincode
echo "Deploying CCaaS chaincode: $CC_NAME"
./network.sh deployCCAAS -ccn "$CC_NAME" -ccp "$CC_PATH"

# Sync crypto into fabric/crypto folder in repo
echo "Syncing Fabric crypto into fabric/crypto repo folder..."
require_dir "$USER_CERT_DIR"
require_dir "$USER_KEY_DIR"
require_file "$PEER_TLS_CA_FILE"

mkdir -p "$CRYPTO_DIR"
rm -f "$CRYPTO_DIR"/*.pem

cp "$USER_CERT_DIR"/* "$CRYPTO_DIR/org1-user1-cert.pem"
cp "$USER_KEY_DIR"/*  "$CRYPTO_DIR/org1-user1-key.pem"
cp "$PEER_TLS_CA_FILE" "$CRYPTO_DIR/org1-peer-tlsca.pem"

# Update connection profile TLS CA PEMs
echo "Updating connection profile TLS CA cert(s)..."
require_file "$CONN_JSON"

python3 - <<PY
import json, pathlib

conn_path = pathlib.Path(r"$CONN_JSON")
peer_ca_path = pathlib.Path(r"$PEER_TLS_CA_FILE")

data = json.loads(conn_path.read_text())

# Update peer TLS CA PEM
data["peers"]["peer0.org1.example.com"]["tlsCACerts"]["pem"] = peer_ca_path.read_text().strip() + "\n"

# Optionally update CA TLS cert in profile if present and file exists
ca_tls_path = pathlib.Path(r"$CA_TLS_CERT_FILE")
if ca_tls_path.exists():
    if "certificateAuthorities" in data and "ca.org1.example.com" in data["certificateAuthorities"]:
        data["certificateAuthorities"]["ca.org1.example.com"].setdefault("tlsCACerts", {})
        data["certificateAuthorities"]["ca.org1.example.com"]["tlsCACerts"]["pem"] = [ca_tls_path.read_text().strip() + "\n"]

conn_path.write_text(json.dumps(data, indent=4))
print("connection-org1.json updated")
PY

# Done
echo "All done."
echo "Network: up, channel: $CHANNEL_NAME, chaincode: $CC_NAME deployed (CCaaS), crypto synced, connection profile updated."