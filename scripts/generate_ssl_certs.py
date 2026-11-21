#!/usr/bin/env python3
"""Cross-platform TLS Certificate Generator for Red Mercury.

Generates high-entropy self-signed SSL/TLS certificates for staging, testing,
and local deployment validation without requiring external openssl binaries.
"""
import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import sys

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: The 'cryptography' package is required. Install via: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def generate_self_signed_cert(
    output_dir: Path,
    domain: str = "redmercury.xerova.com",
    days_valid: int = 365,
    key_size: int = 4096,
) -> None:
    """Generate RSA private key and self-signed X.509 certificate with SAN."""
    output_dir.mkdir(parents=True, exist_ok=True)
    key_path = output_dir / "redmercury.key"
    crt_path = output_dir / "redmercury.crt"

    print(f"Generating {key_size}-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    print("Building X.509 certificate with Subject Alternative Names (SAN)...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Mercury Security"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    now = datetime.now(timezone.utc)
    san_list = [
        x509.DNSName(domain),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_pem)
    # Restrict permissions on POSIX
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

    # Write certificate
    crt_pem = cert.public_bytes(serialization.Encoding.PEM)
    crt_path.write_bytes(crt_pem)
    try:
        os.chmod(crt_path, 0o644)
    except Exception:
        pass

    fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
    formatted_fp = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))

    print("\n[+] SSL/TLS Certificate successfully generated:")
    print(f"  * Private Key:  {key_path.resolve()}")
    print(f"  * Certificate:  {crt_path.resolve()}")
    print(f"  * Common Name:  {domain}")
    print(f"  * SANs:         {[str(s.value) for s in san_list]}")
    print(f"  * Valid Until:  {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  * SHA-256 Fingerprint: {formatted_fp}\n")


def main():
    parser = argparse.ArgumentParser(description="Generate TLS Certificates for Red Mercury")
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "ssl",
        help="Directory to write redmercury.crt and redmercury.key (default: ./ssl)",
    )
    parser.add_argument(
        "--domain",
        "-d",
        type=str,
        default="redmercury.xerova.com",
        help="Primary domain name for common name and SAN (default: redmercury.xerova.com)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Certificate validity period in days (default: 365)",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=4096,
        help="RSA key size in bits (default: 4096)",
    )

    args = parser.parse_args()
    generate_self_signed_cert(
        output_dir=args.output_dir,
        domain=args.domain,
        days_valid=args.days,
        key_size=args.key_size,
    )


if __name__ == "__main__":
    main()
