from django.db import models
from django.conf import settings

class LoginActivity(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "SUCCESS", "Success"
        FAILED_PASSWORD = "FAILED_PASSWORD", "Failed Password"
        FAILED_OTP = "FAILED_OTP", "Failed OTP"
        LOCKED = "LOCKED", "Locked"
        OTP_SENT = "OTP_SENT", "OTP Sent"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="login_activities")
    email = models.EmailField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location_label = models.CharField(max_length=120, blank=True)
    device_name = models.CharField(max_length=120, blank=True)
    user_agent = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices)
    detail = models.TextField(blank=True)
    is_trusted_device = models.BooleanField(default=False)
    is_unusual = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.email} - {self.status} at {self.created_at}"