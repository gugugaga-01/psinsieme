#!/bin/bash
set -e

CERTS_DIR="/app/certs"

# Check if user mounted certs
if [ -f "$CERTS_DIR/ca.pem" ]; then
    echo "[entrypoint] Using mounted certificates from $CERTS_DIR"
    # User has certs — inject --certs-dir if not already specified
    if ! echo "$@" | grep -qE -- "--certs-dir|--cert "; then
        set -- "$@" --certs-dir "$CERTS_DIR"
    fi
    # Default to mtls if --tls-mode not specified
    if ! echo "$@" | grep -qE -- "--tls-mode"; then
        set -- "$@" --tls-mode mtls
    fi
else
    echo "[entrypoint] No certificates found. Generating self-signed cert..."
    mkdir -p "$CERTS_DIR"

    # Generate a self-signed CA + server cert for encrypt-only TLS
    openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
        -keyout "$CERTS_DIR/server-key.pem" \
        -out "$CERTS_DIR/server.pem" \
        -subj "/CN=localhost/O=psinsieme/C=US" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    echo "[entrypoint] Self-signed certificate generated."

    # Inject cert flags if not already specified
    if ! echo "$@" | grep -qE -- "--certs-dir|--cert "; then
        set -- "$@" --cert "$CERTS_DIR/server.pem" --key "$CERTS_DIR/server-key.pem"
    fi
    # Default to tls mode (encrypted, no verification)
    if ! echo "$@" | grep -qE -- "--tls-mode"; then
        set -- "$@" --tls-mode tls
    fi
fi

exec "$@"
