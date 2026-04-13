from django.conf import settings
from django.db import models


class LoginActivity(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "SUCCESS", "Success"
        FAILED_PASSWORD = "FAILED_PASSWORD", "Failed Password"
        OTP_SENT = "OTP_SENT", "OTP Sent"
        FAILED_OTP = "FAILED_OTP", "Failed OTP"
        LOCKED = "LOCKED", "Locked"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="login_activities",
    )
    email = models.EmailField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices)
    detail = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email", "created_at"]),
            models.Index(fields=["status", "created_at"]),
        ]

    def __str__(self):
        return f"{self.email} - {self.status} @ {self.created_at:%Y-%m-%d %H:%M:%S}"
