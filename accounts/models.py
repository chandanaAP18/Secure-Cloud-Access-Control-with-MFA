import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
import pyotp


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Email is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, username=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("role", User.Role.USER)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", User.Role.ADMIN)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        USER = "USER", "User"

    class SecurityQuestion(models.TextChoices):
        PET = "PET", "What was the name of your first pet?"
        SCHOOL = "SCHOOL", "What is the name of your primary school?"
        CITY = "CITY", "In which city were you born?"
        HERO = "HERO", "Who is your childhood hero?"

    username = models.CharField(max_length=150, unique=True, blank=True)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.USER)
    must_change_password = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=20, blank=True)
    security_question = models.CharField(max_length=20, choices=SecurityQuestion.choices, blank=True)
    security_answer_hash = models.CharField(max_length=128, blank=True)
    pin_hash = models.CharField(max_length=128, blank=True)
    voice_phrase = models.CharField(max_length=255, blank=True)
    voice_signature = models.JSONField(default=list, blank=True)
    voice_enabled = models.BooleanField(default=False)
    voice_reference_audio_path = models.CharField(max_length=255, blank=True)
    voice_profile_meta = models.JSONField(default=dict, blank=True)
    totp_secret = models.CharField(max_length=32, blank=True)
    totp_enabled = models.BooleanField(default=False)
    failed_login_count = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return f"{self.get_full_name() or self.email} ({self.role})"

    def set_security_answer(self, answer):
        self.security_answer_hash = make_password(answer.strip().lower())

    def check_security_answer(self, answer):
        if not self.security_answer_hash:
            return False
        return check_password(answer.strip().lower(), self.security_answer_hash)

    def set_pin(self, pin):
        self.pin_hash = make_password(pin)

    def check_pin(self, pin):
        if not self.pin_hash:
            return False
        return check_password(pin, self.pin_hash)

    @staticmethod
    def normalize_voice_phrase(phrase):
        return " ".join((phrase or "").strip().lower().split())

    def set_voice_profile(self, phrase, signature):
        self.voice_phrase = self.normalize_voice_phrase(phrase)
        self.voice_signature = [float(value) for value in (signature or [])]
        self.voice_enabled = bool(self.voice_phrase and self.voice_signature)

    def check_voice_phrase(self, phrase):
        if not self.voice_phrase:
            return False
        return self.voice_phrase == self.normalize_voice_phrase(phrase)

    def compare_voice_signature(self, signature):
        enrolled = [float(value) for value in (self.voice_signature or [])]
        candidate = [float(value) for value in (signature or [])]
        if not enrolled or len(enrolled) != len(candidate):
            return False, None
        distance = sum(abs(left - right) for left, right in zip(enrolled, candidate)) / len(enrolled)
        return distance <= 0.12, distance

    @property
    def has_voice_profile(self):
        return bool(self.voice_enabled and self.voice_reference_audio_path)

    def ensure_totp_secret(self):
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            if self.pk:
                self.save(update_fields=["totp_secret"])
        return self.totp_secret

    def get_totp_uri(self):
        secret = self.ensure_totp_secret()
        return pyotp.TOTP(secret).provisioning_uri(
            name=self.email,
            issuer_name=settings.TOTP_ISSUER,
        )

    def verify_totp(self, code):
        if not self.totp_secret:
            return False
        return pyotp.TOTP(self.totp_secret).verify(code, valid_window=1)

    @property
    def is_locked(self):
        return bool(self.locked_until and timezone.now() < self.locked_until)

def user_document_upload_path(instance, filename):
    """Dynamic path for document uploads organized by user ID."""
    return f"documents/user_{instance.user.id}/{filename}"


class Document(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="documents")
    file = models.FileField(upload_to=user_document_upload_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-uploaded_at"]

    def __str__(self):
        return f"{self.user.email} - {self.file.name}"


class OTPChallenge(models.Model):
    class Factor(models.TextChoices):
        EMAIL = "EMAIL", "Email OTP"
        PHONE = "PHONE", "Phone OTP"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otp_challenges")
    factor = models.CharField(max_length=10, choices=Factor.choices, default=Factor.EMAIL)
    destination = models.CharField(max_length=255, blank=True)
    code_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["expires_at"]),
        ]

    @classmethod
    def create_for_user(cls, user, factor, destination):
        code = "".join(secrets.choice("0123456789") for _ in range(settings.OTP_LENGTH))
        challenge = cls.objects.create(
            user=user,
            factor=factor,
            destination=destination,
            code_hash=cls.hash_code(code),
            expires_at=timezone.now() + timedelta(seconds=settings.OTP_TTL_SECONDS),
        )
        return challenge, code

    @staticmethod
    def hash_code(code):
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @property
    def is_expired(self):
        return timezone.now() >= self.expires_at

    @property
    def is_consumed(self):
        return self.consumed_at is not None

    def mark_consumed(self):
        self.consumed_at = timezone.now()
        self.save(update_fields=["consumed_at"])

    def verify(self, code):
        if self.is_consumed or self.is_expired or self.attempts >= settings.OTP_MAX_ATTEMPTS:
            return False
        self.attempts += 1
        self.save(update_fields=["attempts"])
        return secrets.compare_digest(self.code_hash, self.hash_code(code))


class PasskeyCredential(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="passkeys")
    name = models.CharField(max_length=100, default="Primary Passkey")
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.BinaryField()
    sign_count = models.PositiveIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - {self.name}"


class TrustedDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="trusted_devices")
    token_hash = models.CharField(max_length=64, unique=True)
    device_name = models.CharField(max_length=120)
    user_agent = models.TextField(blank=True)
    last_ip_address = models.GenericIPAddressField(null=True, blank=True)
    location_label = models.CharField(max_length=120, blank=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-last_seen_at"]

    def __str__(self):
        return f"{self.user.email} - {self.device_name}"
