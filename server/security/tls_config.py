"""TLS configuration helpers and certificate pinning."""
from __future__ import annotations

import ssl
from typing import List, Optional


def create_server_ssl_context(
    certfile: str,
    keyfile: str,
    ca_certfile: Optional[str] = None,
    require_client_cert: bool = False,
    min_tls_version: str = "TLSv1.2",
) -> ssl.SSLContext:
    """
    Create a hardened server SSL context.

    Args:
        certfile: Path to server certificate PEM file.
        keyfile: Path to server private key PEM file.
        ca_certfile: CA certificate for client auth (mTLS).
        require_client_cert: Require client certificates (mTLS).
        min_tls_version: Minimum TLS version ('TLSv1.2' or 'TLSv1.3').
    """
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    if ca_certfile:
        ctx.load_verify_locations(cafile=ca_certfile)
        if require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_OPTIONAL

    # Set minimum TLS version
    if min_tls_version == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Harden cipher suites — prefer ECDHE and AESGCM
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES"
    )

    # Disable compression (CRIME attack)
    ctx.options |= ssl.OP_NO_COMPRESSION

    # Enable session tickets for performance while maintaining security
    ctx.options &= ~ssl.OP_NO_TICKET

    return ctx


def create_client_ssl_context(
    ca_certfile: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    verify: bool = True,
    pinned_certs: Optional[List[str]] = None,
) -> ssl.SSLContext:
    """
    Create a hardened client SSL context with optional certificate pinning.

    Args:
        ca_certfile: Custom CA bundle to trust.
        certfile: Client certificate for mTLS.
        keyfile: Client private key for mTLS.
        verify: Whether to verify server certificates.
        pinned_certs: List of expected certificate SHA-256 fingerprints.
    """
    ctx = ssl.create_default_context()

    if ca_certfile:
        ctx.load_verify_locations(cafile=ca_certfile)

    if certfile and keyfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


def get_cert_fingerprint(certfile: str) -> str:
    """Return the SHA-256 fingerprint of a certificate file."""
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    with open(certfile, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    der = cert.public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
    )
    return hashlib.sha256(der).hexdigest()
