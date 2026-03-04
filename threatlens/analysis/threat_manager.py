from threats.models import Threat


def create_threat(post, score, severity, indicators):

    threat = Threat.objects.create(
        post=post,
        severity=severity,
        score=score,
        indicators=", ".join(indicators)
    )

    return threat