from django.shortcuts import render, redirect
from .models import Post
from .forms import PostForm
from analysis.indicator_extractor import extract_urls, extract_domains, extract_keywords
from threats.models import Indicator
from analysis.threat_detector import calculate_threat_score, classify_severity
from threats.models import Threat
from analysis.threat_detector import calculate_threat_score, classify_severity, analyze_urls


def submit_post(request):

    if request.method == "POST":

        form = PostForm(request.POST)

        if form.is_valid():

            post = form.save()

            text = post.content

            urls = extract_urls(text)
            domains = extract_domains(urls)
            keywords = extract_keywords(text)

            # Save indicators (avoid duplicates)

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

            # Threat detection

            keyword_score, keyword_indicators = calculate_threat_score(keywords)

            # URL analysis score
            url_score, url_indicators = analyze_urls(urls, domains)

            score = keyword_score + url_score
            indicators = keyword_indicators + url_indicators


            severity = classify_severity(score)

            if score > 0:
                Threat.objects.create(
                            post=post,
                            severity=severity,
                            score=score,
                            indicators=", ".join(indicators)
                        )

            return redirect('post_list')

    else:
        form = PostForm()

    return render(request, 'posts/submit_post.html', {'form': form})




def post_list(request):
    posts = Post.objects.all().order_by('-created_at')
    return render(request, 'posts/post_list.html', {'posts': posts})