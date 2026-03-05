from django.shortcuts import render, redirect
from .models import Post
from .forms import PostForm


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

    if request.method == "POST":

        form = PostForm(request.POST)

        if form.is_valid():

            post = form.save()
            text = post.content

            # Extract indicators
            urls = extract_urls(text)
            domains = extract_domains(text)
            keywords = extract_keywords(text)
            ips = extract_ips(text)
            hashes = extract_hashes(text)

            # Save indicators
            for url in urls:
                Indicator.objects.get_or_create(
                    indicator_type="url",
                    value=url
                )

            for domain in domains:
                Indicator.objects.get_or_create(
                    indicator_type="domain",
                    value=domain
                )

            for keyword in keywords:
                Indicator.objects.get_or_create(
                    indicator_type="keyword",
                    value=keyword
                )
            for ip in ips:
                Indicator.objects.get_or_create(
                    indicator_type="ip",
                    value=ip
                )


            # Save hash indicators
            for h in hashes:
                Indicator.objects.get_or_create(
                    indicator_type="hash",
                    value=h
                )

            # Threat analysis
            analyze_post(post, keywords, urls, domains, ips, hashes)

            return redirect("post_list")

    else:
        form = PostForm()

    return render(request, "posts/submit_post.html", {"form": form})


def post_list(request):

    posts = Post.objects.all().order_by("-created_at")

    return render(request, "posts/post_list.html", {"posts": posts})