from inventory import CertificateInventory


def main():
    certificate_directory = input("Enter certificate folder path: ").strip()

    inventory = CertificateInventory(certificate_directory)

    try:
        findings = inventory.scan_all()
    except (FileNotFoundError, NotADirectoryError) as error:
        print(f"Error: {error}")
        return

    print("\n===== CRYPTOGRAPHIC INVENTORY =====")
    print("Certificates discovered:", len(findings))

    for finding in findings:
        print("\n-----------------------------")
        print("Certificate:", finding.asset_name)
        print("Certificate Type:", finding.certificate_type)
        print("Key Algorithm:", finding.key_algorithm)
        print("Key Size:", finding.key_size)
        print("Signature:", finding.signature_algorithm)
        print("Cryptographic Strength:", finding.crypto_strength)
        print("Issuer:", finding.issuer)
        print("Subject:", finding.subject)
        print("Serial Number:", finding.serial_number)
        print("Version:", finding.version)
        print("SHA-256 Fingerprint:", finding.fingerprint)
        print("Valid From:", finding.valid_from)
        print("Valid Until:", finding.valid_until)
        print("Expired:", finding.is_expired)
        print("Days Remaining:", finding.days_until_expiry)
        print("Risk Level:", finding.risk_level)
        print("Risk Score:", finding.risk_score)

        if finding.risk_reasons:
            print("Risk Reasons:")
            for reason in finding.risk_reasons:
                print("-", reason)

    inventory.export_json(findings)


if __name__ == "__main__":
    main()
