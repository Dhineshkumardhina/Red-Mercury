#!/usr/bin/env bash
# ==============================================================================
# Red Mercury - Generate SSL/TLS Certificates (Linux / macOS)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SSL_DIR="${REPO_ROOT}/ssl"

mkdir -p "${SSL_DIR}"

if command -v python3 >/dev/null 2>&1; then
    python3 "${SCRIPT_DIR}/generate_ssl_certs.py" --output-dir "${SSL_DIR}"
elif command -v openssl >/dev/null 2>&1; then
    echo "Generating certificates via openssl..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout "${SSL_DIR}/redmercury.key" \
        -out "${SSL_DIR}/redmercury.crt" \
        -subj "/C=US/ST=California/L=San Francisco/O=Red Mercury/CN=redmercury.xerova.com" \
        -addext "subjectAltName=DNS:redmercury.xerova.com,DNS:localhost,IP:127.0.0.1"
    chmod 600 "${SSL_DIR}/redmercury.key"
    chmod 644 "${SSL_DIR}/redmercury.crt"
    echo "✓ Generated self-signed certificates in ${SSL_DIR}"
else
    echo "Error: Neither python3 nor openssl found." >&2
    exit 1
fi
