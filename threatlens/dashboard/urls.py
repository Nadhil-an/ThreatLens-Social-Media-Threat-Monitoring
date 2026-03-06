from django.urls import path
from .views import dashboard, threat_detail, all_threats, threat_chart, download_pdf_report

urlpatterns = [

    path("", dashboard, name="dashboard"),

    path("threat/<int:threat_id>/", threat_detail, name="threat_detail"),

    path("all-threats/", all_threats, name="all_threats"),

    path("threat-chart/", threat_chart, name="threat_chart"),

    path("download-report/", download_pdf_report, name="download_report"),

]