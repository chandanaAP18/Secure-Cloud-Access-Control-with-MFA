import hashlib
import ipaddress
import io
import os
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone

from auditlog.models import LoginActivity

from .models import OTPChallenge, TrustedDevice

ALLOWED_DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".txt",
    ".rtf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".zip",
}

SUSPICIOUS_DOCUMENT_SIGNATURES = [
    b"<?php",
    b"<script",
    b"eval(",
    b"powershell",
    b"cmd.exe",
    b"base64_decode",
]


def scan_document_file(uploaded_file):
    """Scan an uploaded file for disallowed types and suspicious content."""
    file_name = getattr(uploaded_file, "name", "") or ""
    _, extension = os.path.splitext(file_name)
    extension = extension.lower()

    if extension not in ALLOWED_DOCUMENT_EXTENSIONS:
        return False, (
            f"Unsupported document type '{extension or 'unknown'}'. "
            "Allowed types are PDF, DOC, DOCX, TXT, RTF, JPG, PNG, GIF, BMP, and ZIP."
        )

    try:
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
        sample = uploaded_file.read(8192)
    finally:
        if hasattr(uploaded_file, "seek"):
            try:
                uploaded_file.seek(0)
            except io.UnsupportedOperation:
                pass

    if isinstance(sample, str):
        sample = sample.encode("utf-8", errors="ignore")

    content = sample.lower() if isinstance(sample, (bytes, bytearray)) else b""
    for signature in SUSPICIOUS_DOCUMENT_SIGNATURES:
        if signature in content:
            return False, "Document failed the security scan: suspicious content was detected."

    return True, "Document passed the security scan."


def get_client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def describe_device(user_agent):
    user_agent = (user_agent or "").lower()
    browser = "Browser"
    platform = "Device"

    if "edg/" in user_agent:
        browser = "Edge"
    elif "chrome/" in user_agent and "edg/" not in user_agent:
        browser = "Chrome"
    elif "firefox/" in user_agent:
        browser = "Firefox"
    elif "safari/" in user_agent and "chrome/" not in user_agent:
        browser = "Safari"

    if "windows" in user_agent:
        platform = "Windows"
    elif "android" in user_agent:
        platform = "Android"
    elif "iphone" in user_agent or "ipad" in user_agent or "ios" in user_agent:
        platform = "iOS"
    elif "mac os" in user_agent or "macintosh" in user_agent:
        platform = "macOS"
    elif "linux" in user_agent:
        platform = "Linux"

    return f"{browser} on {platform}"


def describe_location(ip_address):
    if not ip_address:
        return "Unknown network"
    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError:
        return "Unknown network"
    if ip_obj.is_loopback:
        return "Localhost"
    if ip_obj.is_private:
        return "Private network"
    if ip_obj.is_reserved:
        return "Reserved network"
    return "Public network"


def get_trusted_device(request, user=None):
    token = request.COOKIES.get(settings.TRUSTED_DEVICE_COOKIE_NAME, "")
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    devices = TrustedDevice.objects.select_related("user")
    if user is not None:
        devices = devices.filter(user=user)
    return devices.filter(token_hash=token_hash).first()


def issue_trusted_device(request, user):
    token = secrets.token_urlsafe(32)
    ip_address = get_client_ip(request)
    device, _ = TrustedDevice.objects.update_or_create(
        user=user,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        defaults={
            "device_name": describe_device(request.META.get("HTTP_USER_AGENT", "")),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:500],
            "last_ip_address": ip_address,
            "location_label": describe_location(ip_address),
        },
    )
    return device, token


def record_known_device(request, device):
    ip_address = get_client_ip(request)
    updates = []
    if device.last_ip_address != ip_address:
        device.last_ip_address = ip_address
        updates.append("last_ip_address")
    location_label = describe_location(ip_address)
    if device.location_label != location_label:
        device.location_label = location_label
        updates.append("location_label")
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]
    if device.user_agent != user_agent:
        device.user_agent = user_agent
        updates.append("user_agent")
    device.device_name = describe_device(user_agent)
    updates.extend(["device_name", "last_seen_at"])
    device.save(update_fields=list(dict.fromkeys(updates)))


def is_unusual_login(*, user, ip_address, device_name, trusted_device=None):
    if trusted_device:
        return False
    previous_success = user.login_activities.filter(status=LoginActivity.Status.SUCCESS).exclude(ip_address__isnull=True)
    if not previous_success.exists():
        return False
    if ip_address and not previous_success.filter(ip_address=ip_address).exists():
        return True
    if device_name and not previous_success.filter(device_name=device_name).exists():
        return True
    return False


def too_many_recent_failures(*, email, ip_address=None):
    window_start = timezone.now() - timedelta(seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    failures = LoginActivity.objects.filter(
        created_at__gte=window_start,
        status__in=[LoginActivity.Status.FAILED_PASSWORD, LoginActivity.Status.LOCKED],
        email=email,
    )
    if failures.count() >= settings.LOGIN_RATE_LIMIT_ATTEMPTS:
        return True
    if ip_address:
        ip_failures = LoginActivity.objects.filter(
            created_at__gte=window_start,
            status__in=[LoginActivity.Status.FAILED_PASSWORD, LoginActivity.Status.LOCKED],
            ip_address=ip_address,
        )
        return ip_failures.count() >= settings.LOGIN_RATE_LIMIT_ATTEMPTS
    return False


def log_login_activity(*, request, email, status, user=None, detail="", is_trusted_device=False, is_unusual=False):
    ip_address = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:500]
    return LoginActivity.objects.create(
        user=user,
        email=email,
        ip_address=ip_address,
        location_label=describe_location(ip_address),
        device_name=describe_device(user_agent),
        user_agent=user_agent,
        status=status,
        detail=detail,
        is_trusted_device=is_trusted_device,
        is_unusual=is_unusual,
    )


def mask_phone_number(phone_number):
    if len(phone_number) <= 4:
        return "*" * len(phone_number)
    return f"{phone_number[:2]}{'*' * (len(phone_number) - 4)}{phone_number[-2:]}"


def issue_otp(user, factor):
    destination = user.email if factor == OTPChallenge.Factor.EMAIL else user.phone_number
    user.otp_challenges.filter(
        consumed_at__isnull=True,
        expires_at__gt=timezone.now(),
        factor=factor,
    ).update(consumed_at=timezone.now())
    challenge, code = OTPChallenge.create_for_user(user, factor=factor, destination=destination)

    if factor == OTPChallenge.Factor.PHONE:
        return challenge, code

    context = {
        "app_name": settings.OTP_APP_NAME,
        "code": code,
        "user": user,
        "expiry_minutes": max(1, settings.OTP_TTL_SECONDS // 60),
    }
    text_body = render_to_string("emails/otp_email.txt", context)
    html_body = render_to_string("emails/otp_email.html", context)
    message = EmailMultiAlternatives(
        subject=settings.OTP_EMAIL_SUBJECT,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email],
    )
    message.attach_alternative(html_body, "text/html")
    message.send(fail_silently=False)
    return challenge, code
