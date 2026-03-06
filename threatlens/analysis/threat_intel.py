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

# -------------------------------
# IP Reputation Check (AbuseIPDB)
# -------------------------------

def check_ip_abuseipdb(ip_address):

    url = "https://api.abuseipdb.com/api/v2/check"
    
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    
    headers = {
        'Accept': 'application/json',
        'Key': settings.ABUSEIPDB_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)
        print("AbuseIPDB STATUS:", response.status_code)

        if response.status_code != 200:
            print("AbuseIPDB Error:", response.text)
            return 0

        data = response.json()
        score = data['data']['abuseConfidenceScore']
        print(f"AbuseIPDB Confidence Score for {ip_address}: {score}%")
        return score

    except Exception as e:
        print("AbuseIPDB API error:", e)
        return 0

# -------------------------------
# URL Screenshotting (URLScan.io)
# -------------------------------

def scan_url_urlscan(target_url):

    url = "https://urlscan.io/api/v1/scan/"

    headers = {
        "API-Key": settings.URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "url": target_url,
        "visibility": "public" 
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        print("URLScan STATUS:", response.status_code)

        if response.status_code == 200:
            data = response.json()
            # The screenshot URL usually follows this format automatically
            uuid = data.get("uuid")
            if uuid:
                screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
                print(f"URLScan Screenshot ready: {screenshot_url}")
                return screenshot_url
        else:
            print("URLScan Error:", response.text)
            return None

    except Exception as e:
        print("URLScan API error:", e)
        return None