from django.shortcuts import render, get_object_or_404
from threats.models import Threat
from analysis.indicator_extractor import extract_urls, extract_domains, extract_ips, extract_hashes, extract_keywords



def dashboard(request):

    total_threats = Threat.objects.count()

    high_threats = Threat.objects.filter(severity="High").count()
    medium_threats = Threat.objects.filter(severity="Medium").count()
    low_threats = Threat.objects.filter(severity="Low").count()

    recent_threats = Threat.objects.order_by('-detected_at')[:5]

    return render(request, "Dashboard/dashboard.html", {
        "total_threats": total_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "recent_threats": recent_threats
    })


def all_threats(request):

    threats = Threat.objects.order_by('-detected_at')

    return render(request, "Dashboard/all_threats.html", {
        "threats": threats
    })


def threat_detail(request, threat_id):

    threat = get_object_or_404(Threat, id=threat_id)

    content = threat.post.content

    urls = extract_urls(content)
    domains = extract_domains(content)
    ips = extract_ips(content)
    hashes = extract_hashes(content)
    keywords = extract_keywords(content)

    context = {
        "threat": threat,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
        "keywords": keywords
    }

    return render(request, "Dashboard/threat_detail.html", context)