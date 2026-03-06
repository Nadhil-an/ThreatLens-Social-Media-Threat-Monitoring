from threats.models import Threat

def create_threat(post, threat_type, score, severity, indicators, vt_detections=None, screenshot_url=None, abuseipdb_score=None):

    threat = Threat.objects.create(
        post=post,
        threat_type=threat_type,
        score=score,
        severity=severity,
        indicators=", ".join(indicators),
        vt_detections=vt_detections,
        screenshot_url=screenshot_url,
        abuseipdb_score=abuseipdb_score
    )

    return threat