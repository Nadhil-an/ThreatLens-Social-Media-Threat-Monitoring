from analysis.threat_intel import check_hash_virustotal


def analyze_hash(file_hash):

    result = check_hash_virustotal(file_hash)

    if not result:
        return None

    malicious = result["malicious"]
    suspicious = result["suspicious"]

    score = 0

    if malicious > 0:
        score += 6

    if suspicious > 0:
        score += 3

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "score": score
    }