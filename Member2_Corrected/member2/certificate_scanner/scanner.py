from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)

from .models import CertificateFinding
from .risk import CertificateRiskAnalyzer


class CertificateScanner:

    def __init__(self, certificate_path):
        self.certificate_path = Path(certificate_path)

    def load_certificate(self):
        data = self.certificate_path.read_bytes()

        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            return x509.load_der_x509_certificate(data)

    def get_public_key_info(self, certificate):
        public_key = certificate.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return "ECC", public_key.curve.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA", public_key.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            return "Ed25519", None
        elif isinstance(public_key, ed448.Ed448PublicKey):
            return "Ed448", None

        return "Unknown", None

    def get_signature_algorithm(self, certificate):
        try:
            return certificate.signature_hash_algorithm.name
        except Exception:
            return "Unknown"

    def get_certificate_identity(self, certificate):
        issuer = certificate.issuer.rfc4514_string()
        subject = certificate.subject.rfc4514_string()
        return issuer, subject

    def get_certificate_metadata(self, certificate):
        serial_number = str(certificate.serial_number)
        version = certificate.version.name
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        return serial_number, version, fingerprint

    def get_certificate_type(self, certificate):
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            is_ca = basic_constraints.ca
        except x509.ExtensionNotFound:
            is_ca = False

        if not is_ca:
            return "END_ENTITY"

        if certificate.issuer == certificate.subject:
            return "ROOT_CA"

        return "INTERMEDIATE_CA"

    def get_validity_info(self, certificate):
        valid_from = certificate.not_valid_before_utc
        valid_until = certificate.not_valid_after_utc
        now = datetime.now(timezone.utc)

        is_expired = now > valid_until
        if is_expired:
            days_until_expiry = 0
        else:
            days_until_expiry = (valid_until - now).days

        return (
            valid_from.isoformat(),
            valid_until.isoformat(),
            is_expired,
            days_until_expiry,
        )

    def scan(self):
        certificate = self.load_certificate()

        key_algorithm, key_size = self.get_public_key_info(certificate)
        signature_algorithm = self.get_signature_algorithm(certificate)
        issuer, subject = self.get_certificate_identity(certificate)
        serial_number, version, fingerprint = self.get_certificate_metadata(certificate)
        certificate_type = self.get_certificate_type(certificate)
        valid_from, valid_until, is_expired, days_until_expiry = self.get_validity_info(
            certificate
        )

        finding = CertificateFinding(
            asset_name=self.certificate_path.name,
            asset_type="certificate",
            certificate_type=certificate_type,
            key_algorithm=key_algorithm,
            key_size=key_size,
            signature_algorithm=signature_algorithm,
            issuer=issuer,
            subject=subject,
            serial_number=serial_number,
            version=version,
            fingerprint=fingerprint,
            valid_from=valid_from,
            valid_until=valid_until,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            crypto_strength="UNKNOWN",
            risk_level="UNKNOWN",
            risk_score=0,
            risk_reasons=[],
        )

        risk_analyzer = CertificateRiskAnalyzer()
        risk_level, risk_score, risk_reasons = risk_analyzer.analyze(finding)

        finding.risk_level = risk_level
        finding.risk_score = risk_score
        finding.risk_reasons = risk_reasons

        return finding
