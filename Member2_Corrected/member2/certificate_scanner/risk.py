class CryptoAlgorithmClassifier:

    def classify(self, finding):
        algorithm = finding.key_algorithm
        key_size = finding.key_size

        if algorithm == "RSA":
            if key_size is None:
                return "UNKNOWN"
            if key_size < 1024:
                return "DEPRECATED"
            elif key_size < 2048:
                return "WEAK"
            elif key_size < 3072:
                return "ACCEPTABLE"
            return "STRONG"

        elif algorithm == "DSA":
            if key_size is None:
                return "UNKNOWN"
            if key_size < 2048:
                return "WEAK"
            return "ACCEPTABLE"

        elif algorithm == "ECC":
            if key_size is None:
                return "UNKNOWN"
            if key_size < 224:
                return "WEAK"
            elif key_size < 256:
                return "ACCEPTABLE"
            return "STRONG"

        elif algorithm in ["Ed25519", "Ed448"]:
            return "STRONG"

        return "UNKNOWN"


class CertificateRiskAnalyzer:

    def analyze(self, finding):
        classifier = CryptoAlgorithmClassifier()
        crypto_strength = classifier.classify(finding)
        finding.crypto_strength = crypto_strength

        score = 0
        risk_reasons = []

        if crypto_strength == "DEPRECATED":
            score += 40
            risk_reasons.append("Certificate uses deprecated cryptography")
        elif crypto_strength == "WEAK":
            score += 25
            risk_reasons.append("Certificate uses weak cryptography")
        elif crypto_strength == "UNKNOWN":
            score += 20
            risk_reasons.append("Cryptographic strength could not be determined")

        if finding.is_expired:
            score += 50
            risk_reasons.append("Certificate has expired")
        elif finding.days_until_expiry is not None:
            if finding.days_until_expiry <= 30:
                score += 30
                risk_reasons.append("Certificate expires within 30 days")
            elif finding.days_until_expiry <= 90:
                score += 15
                risk_reasons.append("Certificate expires within 90 days")

        if finding.key_algorithm == "RSA" and finding.key_size is not None:
            if finding.key_size < 1024:
                score += 50
                risk_reasons.append("RSA key is extremely weak")
            elif finding.key_size < 2048:
                score += 30
                risk_reasons.append("RSA key size is less than 2048 bits")

        if finding.key_algorithm == "DSA":
            if finding.key_size is not None and finding.key_size < 2048:
                score += 30
                risk_reasons.append("DSA key size is less than 2048 bits")

        if finding.signature_algorithm is not None:
            signature = finding.signature_algorithm.lower()
            if "sha1" in signature:
                score += 30
                risk_reasons.append("Certificate uses weak SHA-1 signature algorithm")
            elif "md5" in signature:
                score += 50
                risk_reasons.append("Certificate uses insecure MD5 signature algorithm")

        if finding.key_algorithm == "Unknown":
            score += 30
            risk_reasons.append("Unknown public-key algorithm")

        score = min(score, 100)

        if score >= 76:
            risk_level = "CRITICAL"
        elif score >= 51:
            risk_level = "HIGH"
        elif score >= 26:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return risk_level, score, risk_reasons
