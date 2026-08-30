#!/usr/bin/env bash
set -euo pipefail

readonly OUT_DIR="${1:-/tmp/pqc_tls_certs}"
mkdir -p "${OUT_DIR}"

cat <<'CONF' > "${OUT_DIR}/openssl_mtls.cnf"
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

[v3_server]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
DNS.2 = pqc-server.local

[v3_client]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
CONF

# 1. Generate Root CA (ML-DSA-65)
openssl req -x509 -newkey ML-DSA-65 -days 3650 -nodes     -keyout "${OUT_DIR}/ca.key" -out "${OUT_DIR}/ca.crt"     -config "${OUT_DIR}/openssl_mtls.cnf" -extensions v3_ca 2>/dev/null

# 2. Generate Server Certificate (ML-DSA-65 with SAN)
openssl req -new -newkey ML-DSA-65 -nodes     -keyout "${OUT_DIR}/server.key" -out "${OUT_DIR}/server.csr"     -subj "/CN=127.0.0.1" -config "${OUT_DIR}/openssl_mtls.cnf" 2>/dev/null
openssl x509 -req -in "${OUT_DIR}/server.csr" -CA "${OUT_DIR}/ca.crt" -CAkey "${OUT_DIR}/ca.key" -CAcreateserial     -out "${OUT_DIR}/server.crt" -days 365     -extfile "${OUT_DIR}/openssl_mtls.cnf" -extensions v3_server 2>/dev/null

# 3. Generate Client Certificate (ML-DSA-65)
openssl req -new -newkey ML-DSA-65 -nodes     -keyout "${OUT_DIR}/client.key" -out "${OUT_DIR}/client.csr"     -subj "/CN=pqc-client.local" -config "${OUT_DIR}/openssl_mtls.cnf" 2>/dev/null
openssl x509 -req -in "${OUT_DIR}/client.csr" -CA "${OUT_DIR}/ca.crt" -CAkey "${OUT_DIR}/ca.key" -CAcreateserial     -out "${OUT_DIR}/client.crt" -days 365     -extfile "${OUT_DIR}/openssl_mtls.cnf" -extensions v3_client 2>/dev/null

# 4. Verify Certificates
openssl verify -CAfile "${OUT_DIR}/ca.crt" "${OUT_DIR}/server.crt" >/dev/null
openssl verify -CAfile "${OUT_DIR}/ca.crt" "${OUT_DIR}/client.crt" >/dev/null

echo "PQC TLS Certificates generated in: ${OUT_DIR}"
