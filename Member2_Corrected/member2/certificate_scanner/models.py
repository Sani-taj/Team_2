from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class CertificateFinding:
    asset_name: str
    asset_type: str
    certificate_type: Optional[str]

    key_algorithm: Optional[str]
    key_size: Optional[int]

    signature_algorithm: Optional[str]

    issuer: Optional[str]
    subject: Optional[str]

    serial_number: Optional[str]
    version: Optional[str]
    fingerprint: Optional[str]

    valid_from: Optional[str]
    valid_until: Optional[str]

    is_expired: bool
    days_until_expiry: Optional[int]

    crypto_strength: str

    risk_level: str
    risk_score: int
    risk_reasons: list[str]

    def to_dict(self):
        return asdict(self)
