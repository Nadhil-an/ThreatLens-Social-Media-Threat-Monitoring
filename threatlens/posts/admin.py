from django.contrib import admin
from .models import Post


class PostAdmin(admin.ModelAdmin):
    list_display = ("id", "content", "source", "created_at")
    search_fields = ("content", "source")
    list_filter = ("source", "created_at")


admin.site.register(Post, PostAdmin)