#!/usr/bin/env bash
set -euo pipefail

readonly OUT_DIR="${1:-/tmp/pqc_pki_out}"
mkdir -p "${OUT_DIR}"

# 1. Create minimal OpenSSL config for CA and Leaf
cat <<'CONF' > "${OUT_DIR}/openssl_pki.cnf"
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = Applied PQC Root CA
O = Applied PQC Lab
C = KR

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[v3_leaf]
basicConstraints = CA:false
keyUsage = keyEncipherment
CONF

# 2. Generate Root CA (ML-DSA-65)
openssl req -x509 -newkey ML-DSA-65 -days 3650 -nodes     -keyout "${OUT_DIR}/ca.key" -out "${OUT_DIR}/ca.crt"     -config "${OUT_DIR}/openssl_pki.cnf" -extensions v3_ca 2>/dev/null

# 3. Generate Receiver ML-KEM-768 Keypair
openssl genpkey -algorithm ML-KEM-768 -out "${OUT_DIR}/receiver.key" 2>/dev/null
openssl pkey -in "${OUT_DIR}/receiver.key" -pubout -out "${OUT_DIR}/receiver_pub.pem" 2>/dev/null

# 4. Issue Receiver X.509 Certificate signed by Root CA
openssl x509 -new -CA "${OUT_DIR}/ca.crt" -CAkey "${OUT_DIR}/ca.key" -CAcreateserial     -subj "/CN=pqc-receiver.local/O=Applied PQC Lab/C=KR"     -force_pubkey "${OUT_DIR}/receiver_pub.pem"     -out "${OUT_DIR}/receiver.crt" -days 365     -extfile "${OUT_DIR}/openssl_pki.cnf" -extensions v3_leaf 2>/dev/null

# 5. Verify Certificate Chain
openssl verify -CAfile "${OUT_DIR}/ca.crt" "${OUT_DIR}/receiver.crt" >/dev/null

echo "PQC PKI generated successfully in: ${OUT_DIR}"
