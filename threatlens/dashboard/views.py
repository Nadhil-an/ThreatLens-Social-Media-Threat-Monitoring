from django.shortcuts import render, get_object_or_404
from django.core.paginator import Paginator
from django.http import HttpResponse
from threats.models import Threat

from analysis.indicator_extractor import (
    extract_urls,
    extract_domains,
    extract_ips,
    extract_hashes,
    extract_keywords
)

from analysis.threat_intel import check_hash_virustotal
from analysis.mitre_mapper import map_mitre

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import io


def dashboard(request):

    total_threats = Threat.objects.count()
    high_threats = Threat.objects.filter(severity="High").count()
    medium_threats = Threat.objects.filter(severity="Medium").count()
    low_threats = Threat.objects.filter(severity="Low").count()
    recent_threats = Threat.objects.order_by('-detected_at')[:6]

    return render(request, "Dashboard/dashboard.html", {
        "total_threats": total_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "recent_threats": recent_threats
    })


def all_threats(request):

    threats = Threat.objects.order_by('-detected_at')

    # --- Search & Filter ---
    keyword   = request.GET.get('q', '')
    severity  = request.GET.get('severity', '')
    date_from = request.GET.get('date_from', '')
    date_to   = request.GET.get('date_to', '')

    if keyword:
        threats = threats.filter(post__content__icontains=keyword)

    if severity:
        threats = threats.filter(severity=severity)

    if date_from:
        threats = threats.filter(detected_at__date__gte=date_from)

    if date_to:
        threats = threats.filter(detected_at__date__lte=date_to)

    # --- Pagination (10 per page) ---
    paginator = Paginator(threats, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, "Dashboard/all_threats.html", {
        "page_obj": page_obj,
        "keyword": keyword,
        "severity": severity,
        "date_from": date_from,
        "date_to": date_to,
    })


def threat_detail(request, threat_id):

    threat = get_object_or_404(Threat, id=threat_id)
    content = threat.post.content

    urls     = extract_urls(content)
    domains  = extract_domains(content)
    ips      = extract_ips(content)
    hashes   = extract_hashes(content)
    keywords = extract_keywords(content)

    vt_results = []
    for h in hashes:
        vt = check_hash_virustotal(h)
        if vt:
            vt_results.append({
                "hash": h,
                "malicious": vt["malicious"],
                "harmless": vt["harmless"]
            })

    mitre = map_mitre(threat.threat_type)

    context = {
        "threat": threat,
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
        "keywords": keywords,
        "vt_results": vt_results,
        "mitre": mitre,
    }

    return render(request, "Dashboard/threat_detail.html", context)


def threat_chart(request):

    high   = Threat.objects.filter(severity="High").count()
    medium = Threat.objects.filter(severity="Medium").count()
    low    = Threat.objects.filter(severity="Low").count()

    return render(request, "Dashboard/threat_chart.html", {
        "high": high,
        "medium": medium,
        "low": low,
    })


def download_pdf_report(request):

    threats = Threat.objects.order_by('-detected_at')

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("ThreatLens — Threat Report", styles['Title']))
    elements.append(Spacer(1, 20))

    # Table header
    data = [["#", "Threat Type", "Severity", "Score", "Detected At", "Post (excerpt)"]]

    for i, t in enumerate(threats, start=1):
        data.append([
            str(i),
            t.threat_type or "-",
            t.severity or "-",
            str(t.score) if t.score else "-",
            t.detected_at.strftime("%Y-%m-%d %H:%M") if t.detected_at else "-",
            (t.post.content[:60] + "...") if t.post and len(t.post.content) > 60 else (t.post.content if t.post else "-"),
        ])

    table = Table(data, colWidths=[25, 90, 65, 40, 100, 170])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f1720')),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.HexColor('#00ff9c')),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0, 0), (-1, 0), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#161b22'), colors.HexColor('#0d1117')]),
        ('TEXTCOLOR',  (0, 1), (-1, -1), colors.HexColor('#b8ffe7')),
        ('FONTSIZE',   (0, 1), (-1, -1), 8),
        ('GRID',       (0, 0), (-1, -1), 0.3, colors.HexColor('#00ff9c')),
        ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="threatlens_report.pdf"'
    return response