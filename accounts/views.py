import json
from io import BytesIO
from base64 import urlsafe_b64decode, urlsafe_b64encode
import base64
import random
import string

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.views import LogoutView
from django.core.paginator import Paginator
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator
import qrcode

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, options_to_json
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from auditlog.models import LoginActivity

from .decorators import admin_required, mfa_verified_required
from .forms import (
    CaptchaVerificationForm,
    EmailAuthenticationForm,
    ImageVerificationForm,
    OTPVerificationForm,
    PinVerificationForm,
    RegisterForm,
    SecurityQuestionForm,
    TOTPVerificationForm,
)
from .models import OTPChallenge, PasskeyCredential, User
from .services import issue_otp, log_login_activity, mask_phone_number


IMAGE_CHALLENGE_LIBRARY = {
    "shield": {
        "label": "Shield",
        "hint": "security shield",
        "svg": """
<svg viewBox="0 0 120 120" aria-hidden="true">
    <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#0f766e"></stop>
            <stop offset="100%" stop-color="#123a65"></stop>
        </linearGradient>
    </defs>
    <path d="M60 10L92 22V53C92 73 79 91 60 102C41 91 28 73 28 53V22L60 10Z" fill="url(#shieldGradient)"></path>
    <path d="M60 33L66 47H82L69 56L74 71L60 61L46 71L51 56L38 47H54L60 33Z" fill="#ffffff"></path>
</svg>
""",
    },
    "cloud": {
        "label": "Cloud",
        "hint": "cloud access",
        "svg": """
<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="18" y="58" width="84" height="24" rx="12" fill="#bfdbfe"></rect>
    <circle cx="44" cy="58" r="18" fill="#60a5fa"></circle>
    <circle cx="62" cy="48" r="22" fill="#93c5fd"></circle>
    <circle cx="82" cy="58" r="16" fill="#60a5fa"></circle>
</svg>
""",
    },
    "key": {
        "label": "Key",
        "hint": "access key",
        "svg": """
<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="40" cy="48" r="18" fill="#f59e0b"></circle>
    <circle cx="40" cy="48" r="8" fill="#fff7ed"></circle>
    <rect x="56" y="43" width="38" height="10" rx="5" fill="#fbbf24"></rect>
    <rect x="83" y="53" width="8" height="13" rx="2" fill="#d97706"></rect>
    <rect x="72" y="53" width="8" height="9" rx="2" fill="#d97706"></rect>
</svg>
""",
    },
    "lock": {
        "label": "Lock",
        "hint": "secure lock",
        "svg": """
<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="32" y="50" width="56" height="42" rx="10" fill="#123a65"></rect>
    <path d="M43 50V39C43 29 50 22 60 22C70 22 77 29 77 39V50" fill="none" stroke="#0f766e" stroke-width="10" stroke-linecap="round"></path>
    <circle cx="60" cy="68" r="7" fill="#ccfbf1"></circle>
    <rect x="57" y="68" width="6" height="12" rx="3" fill="#ccfbf1"></rect>
</svg>
""",
    },
}


def get_pending_user(request):
    user_id = request.session.get("pending_mfa_user_id")
    if not user_id:
        return None
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None


def build_mfa_queue(user):
    queue = ["EMAIL"]
    if user.phone_number:
        queue.append("PHONE")
    queue.extend(["CAPTCHA", "IMAGE"])
    if user.totp_enabled:
        queue.append("TOTP")
    if user.security_question and user.security_answer_hash:
        queue.append("QUESTION")
    if user.pin_hash:
        queue.append("PIN")
    if user.passkeys.exists():
        queue.append("PASSKEY")
    return queue


def encode_challenge(challenge):
    return urlsafe_b64encode(challenge).decode("utf-8")


def decode_challenge(value):
    padding = "=" * (-len(value) % 4)
    return urlsafe_b64decode(value + padding)


def generate_totp_qr_data_uri(uri):
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


def next_factor_url(request):
    if request.session.get("mfa_verified"):
        return reverse("accounts:dashboard")
    factor = request.session.get("current_mfa_factor", "EMAIL")
    if factor in {"EMAIL", "PHONE"}:
        return reverse("accounts:verify-otp")
    if factor == "CAPTCHA":
        return reverse("accounts:verify-captcha")
    if factor == "IMAGE":
        return reverse("accounts:verify-image")
    if factor == "TOTP":
        return reverse("accounts:verify-totp")
    if factor == "QUESTION":
        return reverse("accounts:verify-question")
    if factor == "PASSKEY":
        return reverse("accounts:verify-passkey")
    return reverse("accounts:verify-pin")


def set_next_factor(request, user):
    queue = request.session.get("mfa_factor_queue", [])
    if not queue:
        request.session["mfa_verified"] = True
        request.session.pop("pending_mfa_user_id", None)
        request.session.pop("current_mfa_factor", None)
        request.session.pop("mfa_factor_queue", None)
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.SUCCESS,
            user=user,
            detail="All MFA factors completed successfully.",
        )
        messages.success(request, "All verification factors completed successfully.")
        return redirect("accounts:dashboard")

    factor = queue.pop(0)
    request.session["mfa_factor_queue"] = queue
    request.session["current_mfa_factor"] = factor

    if factor in {"EMAIL", "PHONE"}:
        otp_factor = OTPChallenge.Factor.EMAIL if factor == "EMAIL" else OTPChallenge.Factor.PHONE
        try:
            challenge, code = issue_otp(user, otp_factor)
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.OTP_SENT,
                user=user,
                detail=f"{otp_factor.lower()} OTP issued.",
            )
            if otp_factor == OTPChallenge.Factor.PHONE:
                if settings.DEBUG:
                    messages.info(request, f"Demo phone OTP for {mask_phone_number(user.phone_number)}: {code}")
                else:
                    messages.info(request, f"A phone OTP has been sent to {mask_phone_number(user.phone_number)}.")
            else:
                messages.info(request, f"An OTP has been sent to {user.email}.")
        except Exception:
            latest = user.otp_challenges.filter(consumed_at__isnull=True, factor=otp_factor).order_by("-created_at").first()
            if settings.DEBUG and latest:
                fallback_code = "111111" if otp_factor == OTPChallenge.Factor.EMAIL else "222222"
                latest.code_hash = OTPChallenge.hash_code(fallback_code)
                latest.save(update_fields=["code_hash"])
                messages.warning(
                    request,
                    f"{factor.title()} delivery failed in debug mode. Use OTP {fallback_code} to continue.",
                )
                return redirect("accounts:verify-otp")
            else:
                messages.error(request, f"We could not deliver the {factor.lower()} OTP. Please sign in again.")
                logout(request)
                request.session.pop("pending_mfa_user_id", None)
                request.session.pop("current_mfa_factor", None)
                request.session.pop("mfa_factor_queue", None)
                return redirect("accounts:login")
        return redirect("accounts:verify-otp")

    if factor == "CAPTCHA":
        request.session["captcha_challenge"] = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
        messages.info(request, "Complete the CAPTCHA verification step to continue.")
        return redirect("accounts:verify-captcha")

    if factor == "IMAGE":
        image_keys = random.sample(list(IMAGE_CHALLENGE_LIBRARY.keys()), k=4)
        answer_key = random.choice(image_keys)
        request.session["image_challenge"] = {
            "answer": answer_key,
            "options": image_keys,
        }
        messages.info(request, "Select the requested security image to continue.")
        return redirect("accounts:verify-image")

    if factor == "QUESTION":
        messages.info(request, "Please answer your security question.")
        return redirect("accounts:verify-question")

    if factor == "TOTP":
        messages.info(request, "Open your authenticator app and enter the current 6-digit code.")
        return redirect("accounts:verify-totp")

    if factor == "PASSKEY":
        messages.info(request, "Complete biometric or passkey verification on this device.")
        return redirect("accounts:verify-passkey")

    messages.info(request, "Please verify your security PIN.")
    return redirect("accounts:verify-pin")


def home(request):
    if request.user.is_authenticated and request.session.get("mfa_verified"):
        return redirect("accounts:dashboard")
    return render(request, "home.html")


def about(request):
    return render(request, "about.html")


def how_it_works(request):
    return render(request, "how_it_works.html")


class RegisterView(View):
    template_name = "auth/register.html"

    def get(self, request):
        return render(request, self.template_name, {"form": RegisterForm()})

    def post(self, request):
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = user.email
            user.save()
            messages.success(request, "Registration complete. You can sign in now.")
            return redirect("accounts:login")
        return render(request, self.template_name, {"form": form})


class LoginView(View):
    template_name = "auth/login.html"

    def get(self, request):
        return render(request, self.template_name, {"form": EmailAuthenticationForm(request=request)})

    def post(self, request):
        form = EmailAuthenticationForm(request=request, data=request.POST)
        if not form.is_valid():
            log_login_activity(
                request=request,
                email=request.POST.get("username", ""),
                status=LoginActivity.Status.FAILED_PASSWORD,
                detail="Password authentication failed.",
            )
            return render(request, self.template_name, {"form": form})

        user = form.get_user()
        login(request, user)
        request.session["mfa_verified"] = False
        request.session["pending_mfa_user_id"] = str(user.id)
        request.session["mfa_factor_queue"] = build_mfa_queue(user)
        return set_next_factor(request, user)


class CurrentFactorRouterView(View):
    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        factor = request.session.get("current_mfa_factor", "EMAIL")
        if factor in {"EMAIL", "PHONE"}:
            return redirect("accounts:verify-otp")
        if factor == "CAPTCHA":
            return redirect("accounts:verify-captcha")
        if factor == "IMAGE":
            return redirect("accounts:verify-image")
        if factor == "TOTP":
            return redirect("accounts:verify-totp")
        if factor == "QUESTION":
            return redirect("accounts:verify-question")
        if factor == "PASSKEY":
            return redirect("accounts:verify-passkey")
        return redirect("accounts:verify-pin")


class OTPVerifyView(View):
    template_name = "auth/verify_otp.html"

    def get_user(self, request):
        return get_pending_user(request)

    def get(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        selected_factor = request.session.get("current_mfa_factor", "EMAIL")
        factor = OTPChallenge.Factor.EMAIL if selected_factor == "EMAIL" else OTPChallenge.Factor.PHONE
        latest = user.otp_challenges.filter(created_at__isnull=False, factor=factor).order_by("-created_at").first()
        cooldown = 0
        if latest:
            cooldown = max(
                0,
                settings.OTP_RESEND_COOLDOWN_SECONDS - int((timezone.now() - latest.created_at).total_seconds()),
            )
        masked_destination = self.mask_email(user.email) if factor == OTPChallenge.Factor.EMAIL else mask_phone_number(user.phone_number)
        return render(
            request,
            self.template_name,
            {
                "form": OTPVerificationForm(),
                "otp_ttl": max(1, settings.OTP_TTL_SECONDS // 60),
                "resend_cooldown": cooldown,
                "masked_destination": masked_destination,
                "factor_label": "email" if factor == OTPChallenge.Factor.EMAIL else "phone",
            },
        )

    def post(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")

        form = OTPVerificationForm(request.POST)
        selected_factor = request.session.get("current_mfa_factor", "EMAIL")
        factor = OTPChallenge.Factor.EMAIL if selected_factor == "EMAIL" else OTPChallenge.Factor.PHONE
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "otp_ttl": max(1, settings.OTP_TTL_SECONDS // 60),
                    "resend_cooldown": 0,
                    "masked_destination": self.mask_email(user.email) if factor == OTPChallenge.Factor.EMAIL else mask_phone_number(user.phone_number),
                    "factor_label": "email" if factor == OTPChallenge.Factor.EMAIL else "phone",
                },
            )

        challenge = user.otp_challenges.filter(consumed_at__isnull=True, factor=factor).order_by("-created_at").first()
        if not challenge:
            messages.error(request, "No active OTP found. Please sign in again.")
            logout(request)
            return redirect("accounts:login")

        if challenge.verify(form.cleaned_data["otp"]):
            challenge.mark_consumed()
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail=f"{factor.lower()} factor verification succeeded.",
            )
            messages.success(request, f"{factor.title()} factor verified successfully.")
            return set_next_factor(request, user)

        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.FAILED_OTP,
            user=user,
            detail="Incorrect OTP submitted.",
        )
        if challenge.attempts >= settings.OTP_MAX_ATTEMPTS or challenge.is_expired:
            challenge.mark_consumed()
            logout(request)
            messages.error(request, "OTP expired or maximum attempts reached. Please sign in again.")
            return redirect("accounts:login")
        messages.error(request, "Invalid OTP. Please try again.")
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "otp_ttl": max(1, settings.OTP_TTL_SECONDS // 60),
                "resend_cooldown": 0,
                "masked_destination": self.mask_email(user.email) if factor == OTPChallenge.Factor.EMAIL else mask_phone_number(user.phone_number),
                "factor_label": "email" if factor == OTPChallenge.Factor.EMAIL else "phone",
            },
        )

    @staticmethod
    def mask_email(email):
        local, _, domain = email.partition("@")
        if len(local) <= 2:
            masked_local = local[0] + "*" * max(0, len(local) - 1)
        else:
            masked_local = local[:2] + "*" * (len(local) - 2)
        return f"{masked_local}@{domain}"


class OTPResendView(View):
    def post(self, request):
        user_id = request.session.get("pending_mfa_user_id")
        if not user_id:
            messages.error(request, "Your session expired. Please sign in again.")
            return redirect("accounts:login")

        user = User.objects.get(id=user_id)
        selected_factor = request.session.get("current_mfa_factor", "EMAIL")
        factor = OTPChallenge.Factor.EMAIL if selected_factor == "EMAIL" else OTPChallenge.Factor.PHONE
        latest = user.otp_challenges.filter(created_at__isnull=False, factor=factor).order_by("-created_at").first()
        if latest and (timezone.now() - latest.created_at).total_seconds() < settings.OTP_RESEND_COOLDOWN_SECONDS:
            messages.error(request, "Please wait before requesting a new OTP.")
            return redirect("accounts:verify-otp")

        try:
            challenge, code = issue_otp(user, factor)
        except Exception:
            latest = user.otp_challenges.filter(consumed_at__isnull=True, factor=factor).order_by("-created_at").first()
            if settings.DEBUG and latest:
                fallback_code = "111111" if factor == OTPChallenge.Factor.EMAIL else "222222"
                latest.code_hash = OTPChallenge.hash_code(fallback_code)
                latest.save(update_fields=["code_hash"])
                messages.warning(request, f"OTP delivery failed in debug mode. Use OTP {fallback_code}.")
                return redirect("accounts:verify-otp")
            messages.error(request, "OTP email could not be sent. Please verify your email sender settings.")
            return redirect("accounts:verify-otp")
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.OTP_SENT,
            user=user,
            detail=f"{factor.lower()} OTP resent on request.",
        )
        if factor == OTPChallenge.Factor.PHONE and settings.DEBUG:
            messages.info(request, f"Demo phone OTP: {code}")
        messages.success(request, "A new OTP has been sent.")
        return redirect("accounts:verify-otp")


class CaptchaVerifyView(View):
    template_name = "auth/verify_captcha.html"

    def get(self, request):
        user = get_pending_user(request)
        challenge = request.session.get("captcha_challenge")
        if not user or not challenge:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(request, self.template_name, {"form": CaptchaVerificationForm(), "captcha_code": challenge})

    def post(self, request):
        user = get_pending_user(request)
        challenge = request.session.get("captcha_challenge")
        if not user or not challenge:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = CaptchaVerificationForm(request.POST)
        if form.is_valid() and form.cleaned_data["captcha"].strip().upper() == challenge:
            request.session.pop("captcha_challenge", None)
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail="CAPTCHA verification succeeded.",
            )
            messages.success(request, "CAPTCHA verified successfully.")
            return set_next_factor(request, user)
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.FAILED_OTP,
            user=user,
            detail="CAPTCHA verification failed.",
        )
        messages.error(request, "Invalid CAPTCHA. Please try again.")
        return render(request, self.template_name, {"form": form, "captcha_code": challenge})


class ImageVerifyView(View):
    template_name = "auth/verify_image.html"

    def get_context(self, challenge):
        option_keys = challenge.get("options", [])
        choices = [(key, IMAGE_CHALLENGE_LIBRARY[key]["label"]) for key in option_keys]
        form = ImageVerificationForm()
        form.fields["image_choice"].choices = choices
        return {
            "form": form,
            "prompt_label": IMAGE_CHALLENGE_LIBRARY[challenge["answer"]]["label"],
            "image_options": [
                {"key": key, **IMAGE_CHALLENGE_LIBRARY[key]}
                for key in option_keys
            ],
        }

    def get(self, request):
        user = get_pending_user(request)
        challenge = request.session.get("image_challenge")
        if not user or not challenge:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(request, self.template_name, self.get_context(challenge))

    def post(self, request):
        user = get_pending_user(request)
        challenge = request.session.get("image_challenge")
        if not user or not challenge:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = ImageVerificationForm(request.POST)
        form.fields["image_choice"].choices = [(key, IMAGE_CHALLENGE_LIBRARY[key]["label"]) for key in challenge.get("options", [])]
        if form.is_valid() and form.cleaned_data["image_choice"] == challenge.get("answer"):
            request.session.pop("image_challenge", None)
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail="Image verification succeeded.",
            )
            messages.success(request, "Image verification completed successfully.")
            return set_next_factor(request, user)
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.FAILED_OTP,
            user=user,
            detail="Image verification failed.",
        )
        messages.error(request, "Incorrect image selected. Please try again.")
        context = self.get_context(challenge)
        context["form"] = form
        return render(request, self.template_name, context)


class PinVerifyView(View):
    template_name = "auth/verify_pin.html"

    def get_user(self, request):
        return get_pending_user(request)

    def get(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(request, self.template_name, {"form": PinVerificationForm()})

    def post(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = PinVerificationForm(request.POST)
        if form.is_valid() and user.check_pin(form.cleaned_data["pin"]):
            log_login_activity(request=request, email=user.email, status=LoginActivity.Status.SUCCESS, user=user, detail="PIN verification succeeded.")
            messages.success(request, "PIN verified successfully.")
            return set_next_factor(request, user)
        log_login_activity(request=request, email=user.email, status=LoginActivity.Status.FAILED_OTP, user=user, detail="Invalid PIN submitted.")
        messages.error(request, "Invalid PIN. Please try again.")
        return render(request, self.template_name, {"form": form})


class SecurityQuestionVerifyView(View):
    template_name = "auth/verify_question.html"

    def get_user(self, request):
        return get_pending_user(request)

    def get(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(request, self.template_name, {"form": SecurityQuestionForm(), "question": user.get_security_question_display()})

    def post(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = SecurityQuestionForm(request.POST)
        if form.is_valid() and user.check_security_answer(form.cleaned_data["answer"]):
            log_login_activity(request=request, email=user.email, status=LoginActivity.Status.SUCCESS, user=user, detail="Security question answered successfully.")
            messages.success(request, "Security question verified successfully.")
            return set_next_factor(request, user)
        log_login_activity(request=request, email=user.email, status=LoginActivity.Status.FAILED_OTP, user=user, detail="Incorrect security answer submitted.")
        messages.error(request, "Incorrect answer. Please try again.")
        return render(request, self.template_name, {"form": form, "question": user.get_security_question_display()})


class TOTPSetupView(View):
    template_name = "auth/setup_totp.html"

    def get(self, request):
        if not request.user.is_authenticated or not request.session.get("mfa_verified"):
            messages.error(request, "Please complete multi-factor verification first.")
            return redirect("accounts:login")
        user = request.user
        secret = user.ensure_totp_secret()
        user.save(update_fields=["totp_secret"])
        return render(
            request,
            self.template_name,
            {
                "secret": secret,
                "otpauth_uri": user.get_totp_uri(),
                "qr_code_data_uri": generate_totp_qr_data_uri(user.get_totp_uri()),
                "form": TOTPVerificationForm(),
                "totp_enabled": user.totp_enabled,
            },
        )

    def post(self, request):
        if not request.user.is_authenticated or not request.session.get("mfa_verified"):
            messages.error(request, "Please complete multi-factor verification first.")
            return redirect("accounts:login")
        user = request.user
        user.ensure_totp_secret()
        form = TOTPVerificationForm(request.POST)
        if form.is_valid() and user.verify_totp(form.cleaned_data["otp"]):
            user.totp_enabled = True
            user.save(update_fields=["totp_secret", "totp_enabled"])
            messages.success(request, "Authenticator app TOTP enabled successfully.")
            return redirect("accounts:user-dashboard")
        messages.error(request, "Invalid authenticator code. Please try again.")
        return render(
            request,
            self.template_name,
            {
                "secret": user.totp_secret,
                "otpauth_uri": user.get_totp_uri(),
                "qr_code_data_uri": generate_totp_qr_data_uri(user.get_totp_uri()),
                "form": form,
                "totp_enabled": user.totp_enabled,
            },
        )


class TOTPVerifyView(View):
    template_name = "auth/verify_totp.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(request, self.template_name, {"form": TOTPVerificationForm()})

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = TOTPVerificationForm(request.POST)
        if form.is_valid() and user.verify_totp(form.cleaned_data["otp"]):
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail="Authenticator app TOTP verified successfully.",
            )
            messages.success(request, "Authenticator app code verified successfully.")
            return set_next_factor(request, user)
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.FAILED_OTP,
            user=user,
            detail="Invalid authenticator app code submitted.",
        )
        messages.error(request, "Invalid authenticator app code. Please try again.")
        return render(request, self.template_name, {"form": form})


class PasskeyVerifyView(View):
    template_name = "auth/verify_passkey.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(request, self.template_name, {"passkey_count": user.passkeys.count()})


@method_decorator(require_POST, name="dispatch")
class PasskeyRegistrationOptionsView(View):
    def post(self, request):
        if not request.user.is_authenticated or not request.session.get("mfa_verified"):
            return JsonResponse({"error": "Authentication required."}, status=403)

        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id))
            for item in request.user.passkeys.all()
        ]
        options = generate_registration_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_name=request.user.email,
            user_id=str(request.user.id).encode("utf-8"),
            user_display_name=request.user.get_full_name() or request.user.email,
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        request.session["webauthn_registration_challenge"] = encode_challenge(options.challenge)
        return JsonResponse(json.loads(options_to_json(options)))


@method_decorator(require_POST, name="dispatch")
class PasskeyRegistrationVerifyView(View):
    def post(self, request):
        if not request.user.is_authenticated or not request.session.get("mfa_verified"):
            return JsonResponse({"error": "Authentication required."}, status=403)
        challenge = request.session.get("webauthn_registration_challenge")
        if not challenge:
            return JsonResponse({"error": "Registration challenge expired."}, status=400)
        credential = json.loads(request.body.decode("utf-8"))
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=decode_challenge(challenge),
                expected_rp_id=settings.WEBAUTHN_RP_ID,
                expected_origin=settings.WEBAUTHN_ORIGIN,
            )
        except Exception as exc:
            return JsonResponse({"error": str(exc)}, status=400)

        label = credential.get("friendlyName") or f"Passkey {request.user.passkeys.count() + 1}"
        PasskeyCredential.objects.create(
            user=request.user,
            name=label,
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            transports=credential.get("response", {}).get("transports", []),
        )
        request.session.pop("webauthn_registration_challenge", None)
        return JsonResponse({"status": "ok"})


@method_decorator(require_POST, name="dispatch")
class PasskeyAuthenticationOptionsView(View):
    def post(self, request):
        user = get_pending_user(request)
        if not user:
            return JsonResponse({"error": "Authentication required."}, status=403)
        credentials = list(user.passkeys.all())
        if not credentials:
            return JsonResponse({"error": "No passkeys registered."}, status=400)
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id))
            for item in credentials
        ]
        options = generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        request.session["webauthn_authentication_challenge"] = encode_challenge(options.challenge)
        return JsonResponse(json.loads(options_to_json(options)))


@method_decorator(require_POST, name="dispatch")
class PasskeyAuthenticationVerifyView(View):
    def post(self, request):
        user = get_pending_user(request)
        if not user:
            return JsonResponse({"error": "Authentication required."}, status=403)
        challenge = request.session.get("webauthn_authentication_challenge")
        if not challenge:
            return JsonResponse({"error": "Authentication challenge expired."}, status=400)
        credential = json.loads(request.body.decode("utf-8"))
        credential_id = credential.get("id")
        if not credential_id:
            return JsonResponse({"error": "Credential ID missing."}, status=400)
        try:
            stored = user.passkeys.get(credential_id=credential_id)
        except PasskeyCredential.DoesNotExist:
            return JsonResponse({"error": "Passkey not recognized."}, status=404)

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=decode_challenge(challenge),
                expected_rp_id=settings.WEBAUTHN_RP_ID,
                expected_origin=settings.WEBAUTHN_ORIGIN,
                credential_public_key=bytes(stored.public_key),
                credential_current_sign_count=stored.sign_count,
            )
        except Exception as exc:
            return JsonResponse({"error": str(exc)}, status=400)

        stored.sign_count = verification.new_sign_count
        stored.last_used_at = timezone.now()
        stored.save(update_fields=["sign_count", "last_used_at"])
        request.session.pop("webauthn_authentication_challenge", None)
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.SUCCESS,
            user=user,
            detail="Passkey verification succeeded.",
        )
        set_next_factor(request, user)
        return JsonResponse({"status": "ok", "redirect_url": next_factor_url(request)})


@mfa_verified_required
def dashboard(request):
    if request.user.role == User.Role.ADMIN:
        return redirect("accounts:admin-dashboard")
    return redirect("accounts:user-dashboard")


@admin_required
def admin_dashboard(request):
    activities = LoginActivity.objects.select_related("user")[:10]
    users = User.objects.order_by("-date_joined")[:10]
    context = {
        "user_count": User.objects.count(),
        "admin_count": User.objects.filter(role=User.Role.ADMIN).count(),
        "activities": activities,
        "users": users,
    }
    return render(request, "dashboard/admin_dashboard.html", context)


@mfa_verified_required
def user_dashboard(request):
    paginator = Paginator(request.user.login_activities.all(), 10)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/user_dashboard.html", {"page_obj": page_obj})


class AppLogoutView(LogoutView):
    next_page = "accounts:login"
