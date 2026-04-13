from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone

from auditlog.models import LoginActivity

from .models import OTPChallenge


def get_client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_login_activity(*, request, email, status, user=None, detail=""):
    return LoginActivity.objects.create(
        user=user,
        email=email,
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
        status=status,
        detail=detail,
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
