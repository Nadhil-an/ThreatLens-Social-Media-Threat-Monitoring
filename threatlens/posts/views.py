from django.shortcuts import render
from .models import Post
from .forms import PostForm
from threats.models import Threat

from analysis.indicator_extractor import (
    extract_urls,
    extract_domains,
    extract_keywords,
    extract_ips,
    extract_hashes
)
from analysis.threat_detector import analyze_post
from threats.models import Indicator


def submit_post(request):

    analysis_result = None
    bulk_results = []
    error = None

    if request.method == "POST":

        # Path 1: Bulk File Upload
        if request.FILES.get("bulk_file"):
            uploaded = request.FILES["bulk_file"]
            filename = uploaded.name.lower()
            if not (filename.endswith(".txt") or filename.endswith(".csv")):
                error = "Only .txt and .csv files are supported."
            else:
                try:
                    content_bytes = uploaded.read()
                    text_data = content_bytes.decode("utf-8", errors="ignore")
                    lines = [l.strip() for l in text_data.splitlines() if l.strip()]

                    for line in lines:
                        if line.lower().startswith("content") or line.lower().startswith("#"):
                            continue

                        post = Post.objects.create(content=line, source="file_upload")
                        urls     = extract_urls(line)
                        domains  = extract_domains(line)
                        keywords = extract_keywords(line)
                        ips      = extract_ips(line)
                        hashes   = extract_hashes(line)

                        for u in urls: Indicator.objects.get_or_create(indicator_type="url", value=u)
                        for d in domains: Indicator.objects.get_or_create(indicator_type="domain", value=d)
                        for k in keywords: Indicator.objects.get_or_create(indicator_type="keyword", value=k)
                        for i in ips: Indicator.objects.get_or_create(indicator_type="ip", value=i)
                        for h in hashes: Indicator.objects.get_or_create(indicator_type="hash", value=h)

                        threat_type, score, severity, indicators, mitre = analyze_post(
                            post, keywords, urls, domains, ips, hashes
                        )

                        bulk_results.append({
                            "line": line[:80] + ("..." if len(line) > 80 else ""),
                            "threat_type": threat_type,
                            "severity": severity,
                            "score": score,
                        })
                except Exception as e:
                    error = f"Error processing file: {str(e)}"

        # Path 2: Single Text Input
        else:
            form = PostForm(request.POST)
            if form.is_valid():
                post = form.save()
                text = post.content

                urls = extract_urls(text)
                domains = extract_domains(text)
                keywords = extract_keywords(text)
                ips = extract_ips(text)
                hashes = extract_hashes(text)

                for u in urls: Indicator.objects.get_or_create(indicator_type="url", value=u)
                for d in domains: Indicator.objects.get_or_create(indicator_type="domain", value=d)
                for k in keywords: Indicator.objects.get_or_create(indicator_type="keyword", value=k)
                for i in ips: Indicator.objects.get_or_create(indicator_type="ip", value=i)
                for h in hashes: Indicator.objects.get_or_create(indicator_type="hash", value=h)

                threat_type, score, severity, indicators, mitre = analyze_post(
                    post, keywords, urls, domains, ips, hashes
                )

                analysis_result = {
                        "threat_type": threat_type,
                        "score": score,
                        "severity": severity,
                        "indicators": indicators,
                        "urls": urls,
                        "domains": domains,
                        "ips": ips,
                        "hashes": hashes,
                        "mitre_technique": mitre["technique"],
                        "mitre_tactic": mitre["tactic"]
                    }

    form = PostForm()

    return render(
        request,
        "posts/submit_post.html",
        {
            "form": form,
            "analysis": analysis_result,
            "bulk_results": bulk_results,
            "error": error
        }
    )


def post_list(request):

    posts = Post.objects.all().order_by("-created_at")

    for post in posts:
        post.threat = Threat.objects.filter(post=post).first()

    return render(request, "posts/post_list.html", {"posts": posts})