#!/bin/bash
# Generate self-signed CA and per-party certificates for mTLS testing.
# Usage: ./gen_certs.sh [num_parties] [output_dir]
#
# Creates:
#   ca.pem / ca-key.pem          - Certificate Authority
#   party0.pem / party0-key.pem  - Party 0 certificate + key
#   party1.pem / party1-key.pem  - Party 1 certificate + key
#   ...

set -e

NUM_PARTIES=${1:-3}
OUT_DIR=${2:-.}

mkdir -p "$OUT_DIR"

echo "=== Generating CA ==="
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
    -keyout "$OUT_DIR/ca-key.pem" \
    -out "$OUT_DIR/ca.pem" \
    -subj "/CN=MPSI Test CA/O=MPSI/C=US" \
    2>/dev/null

for i in $(seq 0 $((NUM_PARTIES - 1))); do
    echo "=== Generating certificate for party $i ==="

    # Generate key and CSR (RSA-3072 for 128-bit security)
    openssl req -newkey rsa:3072 -nodes \
        -keyout "$OUT_DIR/party${i}-key.pem" \
        -out "$OUT_DIR/party${i}.csr" \
        -subj "/CN=party${i}/O=MPSI/C=US" \
        2>/dev/null

    # Create extensions file for SAN (Subject Alternative Name)
    cat > "$OUT_DIR/party${i}-ext.cnf" <<EOF
[v3_ext]
subjectAltName = DNS:localhost,DNS:party${i},IP:127.0.0.1
EOF

    # Sign with CA
    openssl x509 -req \
        -in "$OUT_DIR/party${i}.csr" \
        -CA "$OUT_DIR/ca.pem" \
        -CAkey "$OUT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$OUT_DIR/party${i}.pem" \
        -days 365 -sha256 \
        -extfile "$OUT_DIR/party${i}-ext.cnf" \
        -extensions v3_ext \
        2>/dev/null

    # Cleanup CSR and ext files
    rm -f "$OUT_DIR/party${i}.csr" "$OUT_DIR/party${i}-ext.cnf"
done

# Generate dealer certificate
echo "=== Generating certificate for dealer ==="
openssl req -newkey rsa:3072 -nodes \
    -keyout "$OUT_DIR/dealer-key.pem" \
    -out "$OUT_DIR/dealer.csr" \
    -subj "/CN=dealer/O=MPSI/C=US" \
    2>/dev/null

cat > "$OUT_DIR/dealer-ext.cnf" <<EOF
[v3_ext]
subjectAltName = DNS:localhost,DNS:dealer,IP:127.0.0.1
EOF

openssl x509 -req \
    -in "$OUT_DIR/dealer.csr" \
    -CA "$OUT_DIR/ca.pem" \
    -CAkey "$OUT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$OUT_DIR/dealer.pem" \
    -days 365 -sha256 \
    -extfile "$OUT_DIR/dealer-ext.cnf" \
    -extensions v3_ext \
    2>/dev/null

rm -f "$OUT_DIR/dealer.csr" "$OUT_DIR/dealer-ext.cnf"
rm -f "$OUT_DIR/ca.srl"

echo "=== Done ==="
echo "CA:      $OUT_DIR/ca.pem, $OUT_DIR/ca-key.pem"
echo "Dealer:  $OUT_DIR/dealer.pem, $OUT_DIR/dealer-key.pem"
for i in $(seq 0 $((NUM_PARTIES - 1))); do
    echo "Party $i: $OUT_DIR/party${i}.pem, $OUT_DIR/party${i}-key.pem"
done
