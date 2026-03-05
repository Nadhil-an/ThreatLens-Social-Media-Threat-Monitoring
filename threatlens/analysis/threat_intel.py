import requests
from django.conf import settings

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# -------------------------------
# Domain Reputation Check
# -------------------------------

def check_domain_virustotal(domain):

    url = f"{VT_BASE_URL}/domains/{domain}"

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY
    }

    try:

        response = requests.get(url, headers=headers)

        print("VT DOMAIN STATUS:", response.status_code)

        if response.status_code != 200:
            print("VirusTotal Domain Error:", response.text)
            return None

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        detections = malicious + suspicious

        print(f"VirusTotal detections for {domain}: {detections}")

        return detections

    except Exception as e:

        print("VirusTotal Domain API error:", e)
        return None


# -------------------------------
# File Hash Reputation Check
# -------------------------------

def check_hash_virustotal(file_hash):

    url = f"{VT_BASE_URL}/files/{file_hash}"

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY
    }

    try:

        response = requests.get(url, headers=headers)

        print("VT HASH STATUS:", response.status_code)

        if response.status_code != 200:
            print("VirusTotal Hash Error:", response.text)
            return None

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

    except Exception as e:

        print("VirusTotal Hash API error:", e)
        return None