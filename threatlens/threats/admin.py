from django.contrib import admin
from .models import Domain, Brand, Indicator, Threat



class DomainAdmin(admin.ModelAdmin):
    list_display = ("domain_name", "reputation_score", "first_seen")
    search_fields = ("domain_name",)


class BrandAdmin(admin.ModelAdmin):
    list_display = ("name", "official_domain")
    search_fields = ("name",)


class IndicatorAdmin(admin.ModelAdmin):
    list_display = ("indicator_type", "value", "created_at")
    search_fields = ("value",)
    list_filter = ("indicator_type",)


class ThreatAdmin(admin.ModelAdmin):
    list_display = ("post", "severity", "score", "indicators", "detected_at")
    search_fields = ("severity",)
    list_filter = ("severity", "detected_at")






admin.site.register(Domain, DomainAdmin)
admin.site.register(Brand, BrandAdmin)
admin.site.register(Indicator, IndicatorAdmin)
admin.site.register(Threat, ThreatAdmin)