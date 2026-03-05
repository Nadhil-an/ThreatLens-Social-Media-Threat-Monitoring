from threats.models import Threat

def create_threat(post, threat_type, score, severity, indicators, vt_detections=None):

    threat = Threat.objects.create(
        post=post,
        threat_type=threat_type,
        score=score,
        severity=severity,
        indicators=", ".join(indicators),
        vt_detections=vt_detections
    )

    return threat