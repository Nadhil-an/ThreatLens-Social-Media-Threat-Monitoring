MITRE_MAPPING = {

    "Phishing": {
        "technique": "T1566 - Phishing",
        "tactic": "Initial Access"
    },

    "Credential Harvesting": {
        "technique": "T1556 - Modify Authentication Process",
        "tactic": "Credential Access"
    },

    "Malware Distribution": {
        "technique": "T1204 - User Execution",
        "tactic": "Execution"
    },

    "Crypto Scam": {
        "technique": "T1566 - Phishing",
        "tactic": "Initial Access"
    },

    "Scam": {
        "technique": "T1566 - Phishing",
        "tactic": "Initial Access"
    },

    "Suspicious": {
        "technique": "T1598 - Phishing for Information",
        "tactic": "Reconnaissance"
    }

}


def map_mitre(threat_type):

    if threat_type in MITRE_MAPPING:
        return MITRE_MAPPING[threat_type]

    return {
        "technique": "Unknown Technique",
        "tactic": "Unknown Tactic"
    }