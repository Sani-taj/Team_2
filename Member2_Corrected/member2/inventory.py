import json
from pathlib import Path

from certificate_scanner.scanner import CertificateScanner


class CertificateInventory:

    def __init__(self, certificate_directory):
        self.certificate_directory = Path(certificate_directory)

    def discover_certificates(self):
        if not self.certificate_directory.exists():
            raise FileNotFoundError(
                f"Certificate folder not found: {self.certificate_directory}"
            )

        if not self.certificate_directory.is_dir():
            raise NotADirectoryError(
                f"Not a directory: {self.certificate_directory}"
            )

        certificates = []

        for file in self.certificate_directory.iterdir():
            if file.is_file() and file.suffix.lower() in [".pem", ".crt", ".cer", ".der"]:
                certificates.append(file)

        return certificates

    def scan_all(self):
        findings = []

        certificates = self.discover_certificates()

        for certificate in certificates:
            try:
                scanner = CertificateScanner(certificate)
                finding = scanner.scan()
                findings.append(finding)
            except Exception as error:
                print(f"Could not scan {certificate.name}: {error}")

        return findings

    def export_json(self, findings, output_file="cryptographic_inventory.json"):
        data = [finding.to_dict() for finding in findings]

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        print(f"\nInventory exported to: {output_file}")
