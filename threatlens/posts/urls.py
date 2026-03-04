from django.urls import path
from . import views

urlpatterns = [
    path('submit/', views.submit_post, name='submit_post'),
    path('', views.post_list, name='post_list'),
]