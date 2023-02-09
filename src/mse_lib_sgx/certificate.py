"""mse_lib_sgx.certificate module."""

import abc
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Optional, ClassVar, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from intel_sgx_ra.quote import Quote
from intel_sgx_ra.ratls import SGX_QUOTE_EXTENSION_OID, get_quote_from_cert

from mse_lib_sgx.sgx_quote import get_quote


class CertificateType(type):
    """CertificateType metaclass."""

    cert_path: ClassVar[Path]
    key_path: ClassVar[Path]
    sk: ClassVar[ec.EllipticCurvePrivateKey]
    expiration_date: ClassVar[datetime]
    cert: ClassVar[x509.Certificate]


class Certificate(metaclass=CertificateType):
    """Certificate abstract class."""

    @abc.abstractmethod
    def __init__(
        self,
        dns_name: str,
        subject: x509.Name,
        root_path: Path,
        expiration_date: datetime,
    ):
        """Abstract init constructor."""

    def write(
        self, cert_path: Path, sk_path: Path, encoding: Encoding = Encoding.PEM
    ) -> None:
        """Write X509 certificate and private key to `cert_path` and `sk_path`."""
        cert_path.write_bytes(self.cert.public_bytes(encoding))
        sk_path.write_bytes(
            self.sk.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
        )


class DebugCertificate(Certificate):
    """DebugCertificate class."""

    def __init__(
        self,
        dns_name: str,
        subject: x509.Name,
        root_path: Path,
        expiration_date: datetime,
    ):
        """Init constructor of DebugCertificate."""
        self.cert_path: Path = root_path / "cert.ratls.pem"
        self.key_path: Path = root_path / "key.ratls.pem"
        self.sk: ec.EllipticCurvePrivateKey = (
            ec.generate_private_key(curve=ec.SECP256R1())
            if not self.key_path.exists()
            else cast(
                ec.EllipticCurvePrivateKey,
                load_pem_private_key(data=self.key_path.read_bytes(), password=None),
            )
        )
        self.expiration_date: datetime = expiration_date
        self.cert: x509.Certificate
        if self.key_path.exists() and self.cert_path.exists():
            self.cert = x509.load_pem_x509_certificate(data=self.cert_path.read_bytes())
        else:
            self.cert = generate_x509(
                dns_name=dns_name,
                subject=subject,
                private_key=self.sk,
                expiration_date=self.expiration_date,
                custom_extension=None,
            )
            self.write(self.cert_path, self.key_path)


class SGXCertificate(Certificate):
    """SGXCertificate class."""

    def __init__(
        self,
        dns_name: str,
        subject: x509.Name,
        root_path: Path,
        expiration_date: datetime,
    ):
        """Init constructor of SGXCertificate."""
        self.cert_path: Path = root_path / "cert.ratls.pem"
        self.key_path: Path = root_path / "key.ratls.pem"
        self.sk: ec.EllipticCurvePrivateKey = (
            ec.generate_private_key(curve=ec.SECP256R1())
            if not self.key_path.exists()
            else cast(
                ec.EllipticCurvePrivateKey,
                load_pem_private_key(data=self.key_path.read_bytes(), password=None),
            )
        )
        self.expiration_date: datetime = expiration_date
        self.cert: x509.Certificate
        self.quote: Quote
        if self.key_path.exists() and self.cert_path.exists():
            self.cert = x509.load_pem_x509_certificate(data=self.cert_path.read_bytes())
            self.quote = get_quote_from_cert(self.cert)
        else:
            self.quote = Quote.from_bytes(
                get_quote(
                    user_report_data=hashlib.sha256(
                        self.sk.public_key().public_bytes(
                            encoding=Encoding.X962,
                            format=PublicFormat.UncompressedPoint,
                        )
                    ).digest()
                )
            )
            self.cert = generate_x509(
                dns_name=dns_name,
                subject=subject,
                private_key=self.sk,
                expiration_date=self.expiration_date,
                custom_extension=x509.UnrecognizedExtension(
                    oid=SGX_QUOTE_EXTENSION_OID, value=bytes(self.quote)
                ),
            )
            self.write(self.cert_path, self.key_path)


def generate_x509(
    dns_name: str,
    subject: x509.Name,
    private_key: ec.EllipticCurvePrivateKey,
    expiration_date: datetime,
    custom_extension: Optional[x509.UnrecognizedExtension] = None,
) -> x509.Certificate:
    """X509 certificate generation."""
    issuer: x509.Name = subject  # issuer=subject for self-signed certificate

    builder: x509.CertificateBuilder = x509.CertificateBuilder()

    builder = (
        builder.subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(expiration_date)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        )
    )

    if custom_extension is not None:
        builder = builder.add_extension(custom_extension, critical=False)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())


def to_wildcard_domain(domain: str) -> str:
    """Add wildcard to first subdomain."""
    if "." not in domain:
        return domain

    subdomains: List[str] = urlparse(f"//{domain}").netloc.split(".")

    if len(subdomains) <= 2:
        return domain

    return f"*.{'.'.join(subdomains[1:])}"
