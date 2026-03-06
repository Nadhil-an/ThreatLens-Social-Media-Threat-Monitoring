from django.db import models
from posts.models import Post


class Domain(models.Model):
    domain_name = models.CharField(max_length=255, unique=True)
    reputation_score = models.IntegerField(default=0)
    first_seen = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain_name


class Brand(models.Model):
    name = models.CharField(max_length=100)
    official_domain = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Indicator(models.Model):
    indicator_type = models.CharField(max_length=50)
    value = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.indicator_type}: {self.value}"


class Threat(models.Model):

    post = models.ForeignKey(Post, on_delete=models.CASCADE)

    threat_type = models.CharField(max_length=100)

    severity = models.CharField(max_length=20)

    score = models.IntegerField()

    indicators = models.TextField()

    vt_detections = models.IntegerField(null=True, blank=True)
    
    screenshot_url = models.URLField(max_length=500, null=True, blank=True)
    
    abuseipdb_score = models.IntegerField(null=True, blank=True)

    detected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.threat_type} - {self.severity}"