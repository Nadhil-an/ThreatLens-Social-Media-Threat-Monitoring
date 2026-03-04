THREAT_SCORES = {

    "keyword": 2,
    "suspicious_domain": 3,
    "brand_impersonation": 4,
    "username_impersonation": 3

}


def calculate_threat_score(indicators):

    score = 0
    reasons = []

    for indicator in indicators:

        if indicator in THREAT_SCORES:

            score += THREAT_SCORES[indicator]
            reasons.append(indicator)

    return score, reasons


def classify_severity(score):

    if score >= 8:
        return "HIGH"

    elif score >= 4:
        return "MEDIUM"

    else:
        return "LOW"