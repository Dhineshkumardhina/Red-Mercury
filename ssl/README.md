# 🔒 Red Mercury - SSL / TLS Certificate Directory

This directory holds the SSL/TLS certificates and private keys mounted into the production Nginx reverse proxy (`redmercury_proxy`).

## Required Certificate Files for Production TLS Termination

When deploying with local TLS termination in the Nginx reverse proxy, place your certificates here:

1. **`redmercury.crt`**: The full-chain SSL/TLS certificate (including intermediate CAs).
2. **`redmercury.key`**: The private key corresponding to `redmercury.crt` (unencrypted, PEM-encoded).

> **Security Warning:**
> Never commit real private keys or production certificates to git! This directory is excluded in `.gitignore` (except for documentation and `.gitkeep`).

---

## Generating Self-Signed Certificates for Staging / Testing

For local testing, CI/CD validation, or staging environments, run the automated cross-platform certificate generator:

```bash
# Using Python (cross-platform, recommended):
python scripts/generate_ssl_certs.py

# Or on Linux / macOS:
bash scripts/generate_ssl_certs.sh

# Or on Windows PowerShell:
.\scripts\generate_ssl_certs.ps1
```

This generates a strong 4096-bit RSA self-signed certificate with Subject Alternative Names (SAN) for:
- `redmercury.xerova.com`
- `localhost`
- `127.0.0.1`

---

## Alternative: TLS Termination at Cloud Load Balancer / Ingress

If your production architecture terminates TLS at an external cloud load balancer (e.g., AWS Application Load Balancer, Google Cloud HTTPS Load Balancer, Cloudflare, or Kubernetes Ingress Controller):

1. The external load balancer handles SSL termination with your managed certificate (ACM, Cloudflare SSL, Let's Encrypt).
2. Traffic reaches Nginx over internal HTTP on port 80.
3. Health check endpoints (`/health`, `/live`, `/ready`) respond directly on HTTP port 80 without redirection.
4. Pass standard forwarding headers:
   - `X-Forwarded-Proto: https`
   - `X-Forwarded-For: <client_ip>`
   - `Host: redmercury.xerova.com`
