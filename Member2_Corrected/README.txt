ECDAT - Member 2
Certificate Discovery, Cryptographic Intelligence and Risk Analysis

Folder structure:

member2/
  certificate_scanner/
    __init__.py
    models.py
    risk.py
    scanner.py
  inventory.py
  main.py

Required Python package:
  cryptography

Run from the member2 folder:
  python main.py

Enter the path of a folder containing .pem, .crt, .cer or .der certificates.

The program discovers certificates, extracts cryptographic and certificate
metadata, classifies certificate type and cryptographic strength, calculates
risk, and exports cryptographic_inventory.json.
