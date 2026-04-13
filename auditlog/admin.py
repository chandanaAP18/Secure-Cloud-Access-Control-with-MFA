from django.contrib import admin

from .models import LoginActivity


@admin.register(LoginActivity)
class LoginActivityAdmin(admin.ModelAdmin):
    list_display = ("email", "status", "ip_address", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("email", "detail", "user_agent")
