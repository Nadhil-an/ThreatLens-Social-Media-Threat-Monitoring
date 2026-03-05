from django.urls import path
from .views import dashboard, threat_detail, all_threats

urlpatterns = [

    path("", dashboard, name="dashboard"),

    path("threat/<int:threat_id>/", threat_detail, name="threat_detail"),

    path("all-threats/", all_threats, name="all_threats"),

]