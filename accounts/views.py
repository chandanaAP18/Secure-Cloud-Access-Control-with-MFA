import json
from io import BytesIO
from base64 import urlsafe_b64decode, urlsafe_b64encode
import base64
import random
import string
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.views import LogoutView
from django.core.paginator import Paginator
from django.db import models
from django.db.models.functions import TruncDate
from django.http import FileResponse, Http404, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
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
    PasswordResetOTPForm,
    PasswordResetRequestForm,
    PinSetupForm,
    PinVerificationForm,
    RegisterIdentityForm,
    RegisterPasswordForm,
    RegisterSecurityForm,
    SecurityQuestionForm,
    SecurityQuestionSetupForm,
    SetPasswordForm,          # Used for setting new password
    TOTPVerificationForm,
    TextCaptchaForm,
    VoiceSetupForm,
    VoiceVerificationForm,
    DocumentUploadForm,
)
from .models import Document, OTPChallenge, PasskeyCredential, User
from .services import (
    describe_device,
    get_client_ip,
    get_trusted_device,
    is_unusual_login,
    issue_otp,
    issue_trusted_device,
    log_login_activity,
    mask_phone_number,
    record_known_device,
    too_many_recent_failures,
)
from .voice_biometrics import (
    enroll_user_voice,
    generate_voice_challenge,
    normalize_phrase,
    phrase_matches_expected,
    verify_user_voice,
)


# Each entry: category, label, hint, svg — multiple variants per category enable "select ALL" challenges.
IMAGE_ITEM_LIBRARY = {
    # --- SHIELD (3 variants) ---
    "shield_a": {
        "category": "shield", "label": "Shield", "hint": "star shield",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <path d="M60 10L92 22V53C92 73 79 91 60 102C41 91 28 73 28 53V22L60 10Z" fill="#0f766e"/>
    <path d="M60 33L66 47H82L69 56L74 71L60 61L46 71L51 56L38 47H54L60 33Z" fill="#ffffff"/>
</svg>""",
    },
    "shield_b": {
        "category": "shield", "label": "Shield", "hint": "checkmark shield",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <path d="M60 14L90 26V50C90 70 76 88 60 98C44 88 30 70 30 50V26L60 14Z" fill="#dbeafe" stroke="#0369a1" stroke-width="3"/>
    <path d="M46 58L56 68L76 42" stroke="#0369a1" stroke-width="5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>""",
    },
    "shield_c": {
        "category": "shield", "label": "Shield", "hint": "guardian shield",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <path d="M60 12L91 24V52C91 72 78 90 60 100C42 90 29 72 29 52V24L60 12Z" fill="#1e3a8a"/>
    <path d="M60 22L83 32V52C83 68 73 82 60 90C47 82 37 68 37 52V32L60 22Z" fill="none" stroke="rgba(255,255,255,0.25)" stroke-width="2"/>
    <circle cx="60" cy="58" r="11" fill="rgba(255,255,255,0.95)"/>
    <circle cx="60" cy="58" r="5" fill="#1e3a8a"/>
</svg>""",
    },
    # --- CERTIFICATE (3 variants) ---
    "cert_a": {
        "category": "certificate", "label": "Certificate", "hint": "security certificate",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="30" y="20" width="60" height="70" rx="4" fill="#dbeafe" stroke="#0284c7" stroke-width="2"/>
    <circle cx="60" cy="35" r="8" fill="#0284c7"/>
    <line x1="45" y1="50" x2="75" y2="50" stroke="#0284c7" stroke-width="2" stroke-linecap="round"/>
    <line x1="45" y1="60" x2="75" y2="60" stroke="#0284c7" stroke-width="2" stroke-linecap="round"/>
    <path d="M35 85L40 78L45 85" fill="#0284c7"/>
    <path d="M75 85L80 78L85 85" fill="#0284c7"/>
</svg>""",
    },
    "cert_b": {
        "category": "certificate", "label": "Certificate", "hint": "award certificate",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="28" y="18" width="64" height="66" rx="5" fill="#fef3c7" stroke="#d97706" stroke-width="2"/>
    <circle cx="60" cy="48" r="16" fill="#fbbf24" stroke="#d97706" stroke-width="2"/>
    <path d="M54 48L57 52L66 42" stroke="#92400e" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    <line x1="40" y1="74" x2="80" y2="74" stroke="#d97706" stroke-width="2" stroke-linecap="round"/>
    <path d="M46 82L60 76L74 82L70 90L60 86L50 90Z" fill="#f59e0b"/>
</svg>""",
    },
    "cert_c": {
        "category": "certificate", "label": "Certificate", "hint": "scroll certificate",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="24" y="28" width="72" height="62" rx="3" fill="#ecfdf5" stroke="#059669" stroke-width="2"/>
    <rect x="24" y="28" width="14" height="62" rx="7" fill="#6ee7b7" stroke="#059669" stroke-width="1.5"/>
    <rect x="82" y="28" width="14" height="62" rx="7" fill="#6ee7b7" stroke="#059669" stroke-width="1.5"/>
    <line x1="48" y1="48" x2="80" y2="48" stroke="#059669" stroke-width="2" stroke-linecap="round"/>
    <line x1="48" y1="58" x2="80" y2="58" stroke="#059669" stroke-width="2" stroke-linecap="round"/>
    <line x1="48" y1="68" x2="72" y2="68" stroke="#059669" stroke-width="2" stroke-linecap="round"/>
    <circle cx="60" cy="82" r="5" fill="#059669"/>
</svg>""",
    },
    # --- LOCK (3 variants) ---
    "lock_a": {
        "category": "lock", "label": "Lock", "hint": "secure lock",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="32" y="50" width="56" height="42" rx="10" fill="#123a65"/>
    <path d="M43 50V39C43 29 50 22 60 22C70 22 77 29 77 39V50" fill="none" stroke="#0f766e" stroke-width="10" stroke-linecap="round"/>
    <circle cx="60" cy="68" r="7" fill="#ccfbf1"/>
    <rect x="57" y="68" width="6" height="12" rx="3" fill="#ccfbf1"/>
</svg>""",
    },
    "lock_b": {
        "category": "lock", "label": "Lock", "hint": "vault lock",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="30" y="48" width="60" height="50" rx="8" fill="#7c3aed"/>
    <path d="M44 48V38C44 28 52 22 60 22C68 22 76 28 76 38V48" fill="none" stroke="#5b21b6" stroke-width="8" stroke-linecap="round"/>
    <circle cx="60" cy="72" r="12" fill="rgba(255,255,255,0.15)" stroke="rgba(255,255,255,0.5)" stroke-width="2"/>
    <circle cx="60" cy="72" r="4" fill="white"/>
    <line x1="60" y1="64" x2="60" y2="70" stroke="white" stroke-width="2" stroke-linecap="round"/>
</svg>""",
    },
    "lock_c": {
        "category": "lock", "label": "Lock", "hint": "open lock",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="32" y="52" width="56" height="42" rx="10" fill="#dc2626"/>
    <path d="M44 52V38" fill="none" stroke="#b91c1c" stroke-width="8" stroke-linecap="round"/>
    <path d="M44 38C44 28 52 22 60 22C70 22 77 30 77 38V30" fill="none" stroke="#dc2626" stroke-width="8" stroke-linecap="round"/>
    <circle cx="60" cy="70" r="7" fill="rgba(255,255,255,0.9)"/>
    <rect x="57" y="70" width="6" height="12" rx="3" fill="rgba(255,255,255,0.9)"/>
</svg>""",
    },
    # --- KEY (3 variants) ---
    "key_a": {
        "category": "key", "label": "Key", "hint": "access key",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="40" cy="48" r="18" fill="#f59e0b"/>
    <circle cx="40" cy="48" r="8" fill="#fff7ed"/>
    <rect x="56" y="43" width="38" height="10" rx="5" fill="#fbbf24"/>
    <rect x="83" y="53" width="8" height="13" rx="2" fill="#d97706"/>
    <rect x="72" y="53" width="8" height="9" rx="2" fill="#d97706"/>
</svg>""",
    },
    "key_b": {
        "category": "key", "label": "Key", "hint": "encryption key",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="38" cy="44" r="16" fill="none" stroke="#6d28d9" stroke-width="5"/>
    <circle cx="38" cy="44" r="6" fill="#6d28d9"/>
    <rect x="52" y="40" width="42" height="8" rx="4" fill="#6d28d9"/>
    <rect x="82" y="48" width="8" height="14" rx="2" fill="#6d28d9"/>
    <rect x="70" y="48" width="8" height="10" rx="2" fill="#6d28d9"/>
</svg>""",
    },
    "key_c": {
        "category": "key", "label": "Key", "hint": "master key",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="40" cy="50" r="18" fill="#059669"/>
    <circle cx="40" cy="50" r="9" fill="rgba(255,255,255,0.2)" stroke="white" stroke-width="2"/>
    <circle cx="40" cy="50" r="4" fill="white"/>
    <rect x="56" y="46" width="38" height="8" rx="4" fill="#059669"/>
    <rect x="83" y="54" width="8" height="12" rx="2" fill="#059669"/>
    <rect x="72" y="54" width="8" height="9" rx="2" fill="#059669"/>
</svg>""",
    },
    # --- LAPTOP (3 variants) ---
    "laptop_a": {
        "category": "laptop", "label": "Laptop", "hint": "secure device",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="25" y="25" width="70" height="50" rx="4" fill="#e0f2fe" stroke="#0369a1" stroke-width="2"/>
    <rect x="30" y="30" width="60" height="40" fill="#ffffff" stroke="#0369a1" stroke-width="1"/>
    <circle cx="60" cy="50" r="8" fill="#0369a1" opacity="0.3"/>
    <rect x="15" y="75" width="90" height="6" rx="3" fill="#0369a1"/>
    <circle cx="40" cy="78" r="2" fill="#ffffff"/>
    <circle cx="60" cy="78" r="2" fill="#ffffff"/>
    <circle cx="80" cy="78" r="2" fill="#ffffff"/>
</svg>""",
    },
    "laptop_b": {
        "category": "laptop", "label": "Laptop", "hint": "locked device",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="22" y="22" width="76" height="56" rx="5" fill="#1e293b" stroke="#334155" stroke-width="2"/>
    <rect x="28" y="28" width="64" height="44" rx="2" fill="#0f172a"/>
    <rect x="12" y="78" width="96" height="8" rx="4" fill="#334155"/>
    <rect x="44" y="78" width="32" height="4" rx="2" fill="#1e293b"/>
    <rect x="52" y="38" width="16" height="18" rx="6" fill="none" stroke="#38bdf8" stroke-width="2"/>
    <path d="M55 44V42C55 39 65 39 65 42V44" fill="none" stroke="#38bdf8" stroke-width="2"/>
    <circle cx="60" cy="50" r="3" fill="#38bdf8"/>
</svg>""",
    },
    "laptop_c": {
        "category": "laptop", "label": "Laptop", "hint": "connected device",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="24" y="24" width="72" height="52" rx="5" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
    <rect x="30" y="30" width="60" height="40" rx="2" fill="white" stroke="#16a34a" stroke-width="1"/>
    <path d="M46 56C52 50 68 50 74 56" stroke="#16a34a" stroke-width="3" fill="none" stroke-linecap="round"/>
    <path d="M51 62C55 58 65 58 69 62" stroke="#16a34a" stroke-width="3" fill="none" stroke-linecap="round"/>
    <circle cx="60" cy="67" r="3" fill="#16a34a"/>
    <rect x="14" y="76" width="92" height="7" rx="3.5" fill="#16a34a"/>
</svg>""",
    },
    # --- NETWORK (3 variants) ---
    "network_a": {
        "category": "network", "label": "Network", "hint": "mesh network",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="30" cy="30" r="8" fill="#7c3aed" stroke="#6d28d9" stroke-width="2"/>
    <circle cx="90" cy="30" r="8" fill="#7c3aed" stroke="#6d28d9" stroke-width="2"/>
    <circle cx="60" cy="70" r="8" fill="#7c3aed" stroke="#6d28d9" stroke-width="2"/>
    <circle cx="30" cy="100" r="8" fill="#7c3aed" stroke="#6d28d9" stroke-width="2"/>
    <circle cx="90" cy="100" r="8" fill="#7c3aed" stroke="#6d28d9" stroke-width="2"/>
    <line x1="30" y1="38" x2="60" y2="62" stroke="#7c3aed" stroke-width="2"/>
    <line x1="90" y1="38" x2="60" y2="62" stroke="#7c3aed" stroke-width="2"/>
    <line x1="60" y1="78" x2="30" y2="92" stroke="#7c3aed" stroke-width="2"/>
    <line x1="60" y1="78" x2="90" y2="92" stroke="#7c3aed" stroke-width="2"/>
</svg>""",
    },
    "network_b": {
        "category": "network", "label": "Network", "hint": "star network",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="60" cy="60" r="10" fill="#0ea5e9" stroke="#0284c7" stroke-width="2"/>
    <circle cx="60" cy="22" r="7" fill="#38bdf8" stroke="#0284c7" stroke-width="2"/>
    <circle cx="98" cy="42" r="7" fill="#38bdf8" stroke="#0284c7" stroke-width="2"/>
    <circle cx="84" cy="94" r="7" fill="#38bdf8" stroke="#0284c7" stroke-width="2"/>
    <circle cx="36" cy="94" r="7" fill="#38bdf8" stroke="#0284c7" stroke-width="2"/>
    <circle cx="22" cy="42" r="7" fill="#38bdf8" stroke="#0284c7" stroke-width="2"/>
    <line x1="60" y1="29" x2="60" y2="50" stroke="#0284c7" stroke-width="2"/>
    <line x1="91" y1="46" x2="70" y2="57" stroke="#0284c7" stroke-width="2"/>
    <line x1="78" y1="88" x2="67" y2="68" stroke="#0284c7" stroke-width="2"/>
    <line x1="42" y1="88" x2="53" y2="68" stroke="#0284c7" stroke-width="2"/>
    <line x1="29" y1="46" x2="50" y2="57" stroke="#0284c7" stroke-width="2"/>
</svg>""",
    },
    "network_c": {
        "category": "network", "label": "Network", "hint": "ring network",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="60" cy="60" r="30" fill="none" stroke="#818cf8" stroke-width="2" stroke-dasharray="5 3"/>
    <circle cx="60" cy="30" r="7" fill="#6366f1" stroke="#4f46e5" stroke-width="2"/>
    <circle cx="89" cy="45" r="7" fill="#6366f1" stroke="#4f46e5" stroke-width="2"/>
    <circle cx="89" cy="75" r="7" fill="#6366f1" stroke="#4f46e5" stroke-width="2"/>
    <circle cx="60" cy="90" r="7" fill="#6366f1" stroke="#4f46e5" stroke-width="2"/>
    <circle cx="31" cy="75" r="7" fill="#6366f1" stroke="#4f46e5" stroke-width="2"/>
    <circle cx="31" cy="45" r="7" fill="#6366f1" stroke="#4f46e5" stroke-width="2"/>
</svg>""",
    },
    # --- CLOUD (2 variants, distractor) ---
    "cloud_a": {
        "category": "cloud", "label": "Cloud", "hint": "cloud storage",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="18" y="58" width="84" height="24" rx="12" fill="#bfdbfe"/>
    <circle cx="44" cy="58" r="18" fill="#60a5fa"/>
    <circle cx="62" cy="48" r="22" fill="#93c5fd"/>
    <circle cx="82" cy="58" r="16" fill="#60a5fa"/>
</svg>""",
    },
    "cloud_b": {
        "category": "cloud", "label": "Cloud", "hint": "cloud upload",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <circle cx="42" cy="54" r="18" fill="#bae6fd"/>
    <circle cx="64" cy="42" r="22" fill="#7dd3fc"/>
    <circle cx="82" cy="54" r="16" fill="#bae6fd"/>
    <rect x="18" y="58" width="84" height="18" rx="9" fill="#bae6fd"/>
    <line x1="60" y1="80" x2="60" y2="100" stroke="#0369a1" stroke-width="3" stroke-linecap="round"/>
    <path d="M52 88L60 80L68 88" stroke="#0369a1" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>""",
    },
    # --- FINGERPRINT (2 variants, distractor) ---
    "finger_a": {
        "category": "fingerprint", "label": "Fingerprint", "hint": "biometric access",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <g fill="none" stroke="#059669" stroke-width="3" stroke-linecap="round">
        <path d="M60 15C50 15 42 23 42 35"/>
        <path d="M60 15C70 15 78 23 78 35"/>
        <path d="M45 45C45 35 50 28 60 28C70 28 75 35 75 45"/>
        <path d="M40 55C40 40 48 30 60 30C72 30 80 40 80 55"/>
        <path d="M42 68C42 50 48 35 60 32C72 35 78 50 78 68"/>
        <path d="M45 80C45 60 50 40 60 35C70 40 75 60 75 80"/>
        <circle cx="60" cy="95" r="3" fill="#059669"/>
    </g>
</svg>""",
    },
    "finger_b": {
        "category": "fingerprint", "label": "Fingerprint", "hint": "fingerprint scan",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <g fill="none" stroke="#dc2626" stroke-width="2.5" stroke-linecap="round">
        <path d="M60 18C48 18 38 28 38 40"/>
        <path d="M60 18C72 18 82 28 82 40"/>
        <path d="M42 52C42 38 50 28 60 26C70 28 78 38 78 52"/>
        <path d="M36 64C36 46 46 32 60 28C74 32 84 46 84 64"/>
        <path d="M38 76C38 54 46 36 60 30C74 36 82 54 82 76"/>
        <path d="M40 88C40 62 48 42 60 34C72 42 80 62 80 88"/>
        <circle cx="60" cy="100" r="3" fill="#dc2626"/>
    </g>
</svg>""",
    },
    # --- EYE (distractor) ---
    "eye_a": {
        "category": "eye", "label": "Eye", "hint": "view access",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <ellipse cx="60" cy="60" rx="35" ry="20" fill="none" stroke="#1e40af" stroke-width="2"/>
    <circle cx="60" cy="60" r="12" fill="#1e40af"/>
    <circle cx="60" cy="60" r="6" fill="#ffffff"/>
</svg>""",
    },
    # --- SERVER (2 variants, distractor) ---
    "server_a": {
        "category": "server", "label": "Server", "hint": "server rack",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="30" y="25" width="60" height="20" rx="2" fill="#f3e8ff" stroke="#7c3aed" stroke-width="2"/>
    <rect x="30" y="50" width="60" height="20" rx="2" fill="#f3e8ff" stroke="#7c3aed" stroke-width="2"/>
    <rect x="30" y="75" width="60" height="20" rx="2" fill="#f3e8ff" stroke="#7c3aed" stroke-width="2"/>
    <circle cx="45" cy="35" r="2" fill="#7c3aed"/>
    <circle cx="45" cy="60" r="2" fill="#7c3aed"/>
    <circle cx="45" cy="85" r="2" fill="#7c3aed"/>
</svg>""",
    },
    "server_b": {
        "category": "server", "label": "Server", "hint": "data center",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="28" y="20" width="64" height="18" rx="3" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
    <rect x="28" y="43" width="64" height="18" rx="3" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
    <rect x="28" y="66" width="64" height="18" rx="3" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
    <circle cx="44" cy="29" r="3" fill="#34d399"/>
    <circle cx="44" cy="52" r="3" fill="#34d399"/>
    <circle cx="44" cy="75" r="3" fill="#f59e0b"/>
    <rect x="52" y="26" width="20" height="6" rx="2" fill="#334155"/>
    <rect x="52" y="49" width="20" height="6" rx="2" fill="#334155"/>
    <rect x="52" y="72" width="20" height="6" rx="2" fill="#334155"/>
    <rect x="28" y="89" width="64" height="10" rx="3" fill="#0f172a"/>
</svg>""",
    },
    # --- BUS (3 variants, for CAPTCHA) ---
    "bus_a": {
        "category": "bus", "label": "Bus", "hint": "city bus",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="20" y="30" width="80" height="50" rx="8" fill="#ef4444"/>
    <rect x="25" y="35" width="70" height="25" rx="4" fill="#f8fafc"/>
    <rect x="30" y="38" width="15" height="18" fill="#94a3b8"/>
    <rect x="52" y="38" width="15" height="18" fill="#94a3b8"/>
    <rect x="74" y="38" width="15" height="18" fill="#94a3b8"/>
    <circle cx="35" cy="85" r="8" fill="#1e293b"/>
    <circle cx="85" cy="85" r="8" fill="#1e293b"/>
    <rect x="20" y="70" width="80" height="5" fill="#991b1b"/>
</svg>""",
    },
    "bus_b": {
        "category": "bus", "label": "Bus", "hint": "school bus",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="15" y="35" width="90" height="45" rx="4" fill="#f59e0b"/>
    <rect x="15" y="40" width="20" height="25" fill="#94a3b8"/>
    <rect x="40" y="40" width="15" height="20" fill="#94a3b8"/>
    <rect x="60" y="40" width="15" height="20" fill="#94a3b8"/>
    <rect x="80" y="40" width="15" height="20" fill="#94a3b8"/>
    <circle cx="30" cy="85" r="10" fill="#1e293b"/>
    <circle cx="90" cy="85" r="10" fill="#1e293b"/>
    <rect x="15" y="70" width="90" height="4" fill="#000000"/>
    <rect x="15" y="60" width="90" height="2" fill="#000000"/>
</svg>""",
    },
    "bus_c": {
        "category": "bus", "label": "Bus", "hint": "tourist bus",
        "svg": """<svg viewBox="0 0 120 120" aria-hidden="true">
    <rect x="20" y="25" width="80" height="55" rx="10" fill="#3b82f6"/>
    <rect x="20" y="30" width="80" height="30" fill="#bfdbfe"/>
    <circle cx="35" cy="85" r="9" fill="#1e293b"/>
    <circle cx="85" cy="85" r="9" fill="#1e293b"/>
    <rect x="25" y="65" width="70" height="3" fill="#1d4ed8"/>
</svg>""",
    },
}

# Pre-computed category → [keys] mapping used when generating challenges.
_IMAGE_CATEGORIES: dict[str, list[str]] = {}
for _k, _v in IMAGE_ITEM_LIBRARY.items():
    _IMAGE_CATEGORIES.setdefault(_v["category"], []).append(_k)


def get_webauthn_rp_id(request):
    host = request.get_host().split(":")[0].strip().lower()
    if host in {"localhost", "127.0.0.1"}:
        return host
    return settings.WEBAUTHN_RP_ID


def get_webauthn_origin(request):
    return f"{request.scheme}://{request.get_host()}"


def get_pending_user(request):
    user_id = request.session.get("pending_mfa_user_id")
    if not user_id:
        return None
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None


def build_mfa_queue(user, trusted_device=None, is_signup=False):
    """
    Builds the sequential MFA queue.
    Email OTP, checkbox CAPTCHA, image verification, and text CAPTCHA
    always run for both signup and login before account-specific factors.
    """
    queue = ["EMAIL", "CAPTCHA", "IMAGE", "TEXT_CAPTCHA"]
    
    if is_signup:
        if user.security_question and user.security_answer_hash:
            queue.append("QUESTION")
        if user.pin_hash:
            queue.append("PIN")
        queue.append("VOICE_SETUP")
        # Registration must finish by enrolling an authenticator app so the same factor family
        # is available on later sign-ins.
        queue.append("TOTP_SETUP")
        queue.append("PASSKEY_SETUP")
    else:
        has_question = bool(user.security_question and user.security_answer_hash)
        has_pin = bool(user.pin_hash)
        has_voice = bool(user.has_voice_profile)
        has_totp = bool(user.totp_enabled)
        requires_setup_recovery = not (has_question and has_pin and has_voice and has_totp)

        queue.append("QUESTION" if has_question else "QUESTION_SETUP")
        queue.append("PIN" if has_pin else "PIN_SETUP")
        queue.append("VOICE" if has_voice else "VOICE_SETUP")
        queue.append("TOTP" if has_totp else "TOTP_SETUP")
        if user.passkeys.exists():
            queue.append("PASSKEY")
        elif requires_setup_recovery:
            queue.append("PASSKEY_SETUP")
        return queue
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


MFA_FACTOR_META = {
    "EMAIL": {"short": "Email OTP", "title": "Verify Email OTP"},
    "PHONE": {"short": "Phone OTP", "title": "Verify Phone OTP"},
    "CAPTCHA": {"short": "Not Robot", "title": "Security Check"},
    "IMAGE": {"short": "Image Check", "title": "Image Verification"},
    "TEXT_CAPTCHA": {"short": "Text Verify", "title": "Text Verification"},
    "QUESTION_SETUP": {"short": "Set Up Q", "title": "Set Up Security Question"},
    "QUESTION": {"short": "Security Q", "title": "Security Question"},
    "PIN_SETUP": {"short": "Set Up PIN", "title": "Set Up PIN"},
    "PIN": {"short": "PIN", "title": "Verify PIN"},
    "VOICE_SETUP": {"short": "Set Up Voice", "title": "Set Up Voice ID"},
    "VOICE": {"short": "Voice ID", "title": "Voice Verification"},
    "TOTP": {"short": "TOTP", "title": "Authenticator App"},
    "TOTP_SETUP": {"short": "Set Up TOTP", "title": "Set Up Authenticator"},
    "PASSKEY_SETUP": {"short": "Set Up Passkey", "title": "Set Up Passkey"},
    "PASSKEY": {"short": "Passkey", "title": "Passkey Verification"},
}


def build_mfa_page_context(request, *, heading, subheading):
    current_factor = request.session.get("current_mfa_factor")
    remaining_queue = request.session.get("mfa_factor_queue", [])
    all_factors = request.session.get("mfa_all_steps")
    total_steps = request.session.get("mfa_total_steps")
    ordered_factors = list(all_factors or (([current_factor] if current_factor else []) + list(remaining_queue)))
    if not total_steps:
        total_steps = len(ordered_factors)

    steps = []
    completed_count = max(0, total_steps - len(remaining_queue) - (1 if current_factor else 0))
    for index, factor in enumerate(ordered_factors, start=1):
        meta = MFA_FACTOR_META.get(factor, {"short": factor.title(), "title": factor.title()})
        if factor == current_factor:
            state = "current"
        elif index <= completed_count:
            state = "complete"
        else:
            state = "upcoming"
        steps.append(
            {
                "index": index,
                "factor": factor,
                "label": meta["short"],
                "state": state,
            }
        )

    current_index = completed_count + 1 if current_factor else total_steps
    return {
        "mfa_heading": heading,
        "mfa_subheading": subheading,
        "mfa_steps": steps,
        "mfa_current_index": current_index,
        "mfa_total_steps": total_steps,
    }


def get_or_issue_voice_challenge(request, *, refresh=False):
    stored_phrase = request.session.get("voice_challenge_phrase")
    issued_at = request.session.get("voice_challenge_issued_at")
    expired = not issued_at or (timezone.now().timestamp() - issued_at) > settings.VOICE_CHALLENGE_TTL_SECONDS
    if refresh or not stored_phrase or expired:
        stored_phrase = generate_voice_challenge()
        request.session["voice_challenge_phrase"] = stored_phrase
        request.session["voice_challenge_issued_at"] = timezone.now().timestamp()
    return stored_phrase


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
    if factor == "TEXT_CAPTCHA":
        return reverse("accounts:verify-text-captcha")
    if factor == "TOTP":
        return reverse("accounts:verify-totp")
    if factor == "QUESTION_SETUP":
        return reverse("accounts:verify-question-setup")
    if factor == "QUESTION":
        return reverse("accounts:verify-question")
    if factor == "PIN_SETUP":
        return reverse("accounts:verify-pin-setup")
    if factor == "VOICE_SETUP":
        return reverse("accounts:verify-voice-setup")
    if factor == "VOICE":
        return reverse("accounts:verify-voice")
    if factor == "PASSKEY":
        return reverse("accounts:verify-passkey")
    if factor == "PASSKEY_SETUP":
        return reverse("accounts:verify-passkey-setup")
    if factor == "TOTP_SETUP":
        return reverse("accounts:verify-totp-setup")
    return reverse("accounts:verify-pin")


def set_next_factor(request, user):
    queue = request.session.get("mfa_factor_queue", [])
    if not queue:
        request.session["mfa_verified"] = True
        request.session.pop("pending_mfa_user_id", None)
        request.session.pop("current_mfa_factor", None)
        request.session.pop("mfa_factor_queue", None)
        request.session.pop("mfa_all_steps", None)
        request.session.pop("mfa_total_steps", None)
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.SUCCESS,
            user=user,
            detail="All MFA factors completed successfully.",
            is_trusted_device=request.session.get("trusted_device_recognized", False),
            is_unusual=request.session.get("unusual_login_detected", False),
        )
        response = redirect("accounts:dashboard")
        trusted_device = get_trusted_device(request, user)
        if trusted_device:
            record_known_device(request, trusted_device)
        else:
            _, token = issue_trusted_device(request, user)
            response.set_cookie(
                settings.TRUSTED_DEVICE_COOKIE_NAME,
                token,
                max_age=settings.TRUSTED_DEVICE_MAX_AGE,
                httponly=True,
                samesite="Lax",
            )
        if request.session.get("trusted_device_recognized"):
            messages.success(request, "Congratulations. You have successfully logged in to your account. All verification factors were completed and this trusted device was recognized.")
        else:
            messages.success(request, "Congratulations. You have successfully logged in to your account. All verification factors were completed and this device is now remembered as trusted.")
        request.session.pop("trusted_device_recognized", None)
        request.session.pop("unusual_login_detected", None)
        return response

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
                request.session.pop("mfa_all_steps", None)
                request.session.pop("mfa_total_steps", None)
                return redirect("accounts:login")
        return redirect("accounts:verify-otp")

    if factor == "CAPTCHA":
        messages.info(request, "Complete the CAPTCHA verification step to continue.")
        return redirect("accounts:verify-captcha")

    if factor == "IMAGE":
        target_cat = random.choice(list(_IMAGE_CATEGORIES.keys()))
        cat_keys = _IMAGE_CATEGORIES[target_cat]
        # For a 9-image grid, we want 2-4 correct images
        num_correct = min(len(cat_keys), random.randint(2, 4))
        correct_keys = random.sample(cat_keys, k=num_correct)
        
        other_cats = [c for c in _IMAGE_CATEGORIES if c != target_cat]
        num_distractors = 9 - num_correct
        
        # Pick distractors from other categories
        distractor_keys = []
        while len(distractor_keys) < num_distractors:
            cat = random.choice(other_cats)
            key = random.choice(_IMAGE_CATEGORIES[cat])
            if key not in distractor_keys:
                distractor_keys.append(key)
                
        option_keys = correct_keys + distractor_keys
        random.shuffle(option_keys)
        request.session["image_challenge"] = {
            "target_category": target_cat,
            "target_label": IMAGE_ITEM_LIBRARY[correct_keys[0]]["label"],
            "correct_keys": correct_keys,
            "option_keys": option_keys,
        }
        messages.info(request, "Select all matching security images to continue.")
        return redirect("accounts:verify-image")

    if factor == "TEXT_CAPTCHA":
        captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        request.session["text_captcha"] = captcha_text
        messages.info(request, "Please enter the text verification code shown below.")
        return redirect("accounts:verify-text-captcha")

    if factor == "QUESTION":
        messages.info(request, "Please answer your security question.")
        return redirect("accounts:verify-question")

    if factor == "QUESTION_SETUP":
        messages.info(request, "Set up your security question to continue.")
        return redirect("accounts:verify-question-setup")

    if factor == "PIN_SETUP":
        messages.info(request, "Create your security PIN to continue.")
        return redirect("accounts:verify-pin-setup")

    if factor == "VOICE_SETUP":
        messages.info(request, "Record a voice sample and save your voice passphrase to continue.")
        return redirect("accounts:verify-voice-setup")

    if factor == "VOICE":
        messages.info(request, "Speak your saved voice passphrase to continue.")
        return redirect("accounts:verify-voice")

    if factor == "TOTP":
        messages.info(request, "Open your authenticator app and enter the current 6-digit code.")
        return redirect("accounts:verify-totp")

    if factor == "TOTP_SETUP":
        user.ensure_totp_secret()
        messages.info(request, "Scan the QR code with your authenticator app to enable two-factor authentication.")
        return redirect("accounts:verify-totp-setup")

    if factor == "PASSKEY_SETUP":
        messages.info(request, "Set up a passkey on this device to finish registration.")
        return redirect("accounts:verify-passkey-setup")

    if factor == "PASSKEY":
        messages.info(request, "Complete passkey verification on this device to finish the MFA flow.")
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


REGISTER_STEPS = [
    {
        "key": "identity",
        "title": "Create your profile",
        "description": "Add your personal details and the email you will use to sign in.",
        "form_class": RegisterIdentityForm,
    },
    {
        "key": "password",
        "title": "Create your password",
        "description": "Set the password that protects your SecureCloud account.",
        "form_class": RegisterPasswordForm,
    },
    {
        "key": "security",
        "title": "Set your recovery factors",
        "description": "Choose your security question, answer, PIN, and confirm the registration CAPTCHA.",
        "form_class": RegisterSecurityForm,
    },
]


def get_register_step_index(request):
    raw_value = request.session.get("register_step_index", 0)
    try:
        index = int(raw_value)
    except (TypeError, ValueError):
        index = 0
    return max(0, min(index, len(REGISTER_STEPS) - 1))


def get_register_session_data(request):
    return dict(request.session.get("register_form_data", {}))


def save_register_session_data(request, cleaned_data):
    data = get_register_session_data(request)
    for key, value in cleaned_data.items():
        if key == "captcha_checkbox":
            continue
        data[key] = value
    request.session["register_form_data"] = data


def clear_register_session(request):
    request.session.pop("register_step_index", None)
    request.session.pop("register_form_data", None)


def build_register_context(request, form):
    step_index = get_register_step_index(request)
    step = REGISTER_STEPS[step_index]
    return {
        "form": form,
        "register_step_index": step_index + 1,
        "register_total_steps": len(REGISTER_STEPS),
        "register_step_key": step["key"],
        "register_step_title": step["title"],
        "register_step_description": step["description"],
        "register_steps": [
            {
                "index": index + 1,
                "label": item["title"],
                "state": "current" if index == step_index else ("complete" if index < step_index else "upcoming"),
            }
            for index, item in enumerate(REGISTER_STEPS)
        ],
    }


class RegisterView(View):
    template_name = "auth/register.html"

    def get(self, request):
        step_index = get_register_step_index(request)
        step = REGISTER_STEPS[step_index]
        initial = get_register_session_data(request)
        form = step["form_class"](initial=initial)
        return render(request, self.template_name, build_register_context(request, form))

    def post(self, request):
        if "go_back" in request.POST:
            current_index = get_register_step_index(request)
            request.session["register_step_index"] = max(0, current_index - 1)
            step = REGISTER_STEPS[get_register_step_index(request)]
            form = step["form_class"](initial=get_register_session_data(request))
            return render(request, self.template_name, build_register_context(request, form))

        step_index = get_register_step_index(request)
        step = REGISTER_STEPS[step_index]
        form = step["form_class"](request.POST)
        if not form.is_valid():
            return render(request, self.template_name, build_register_context(request, form))

        save_register_session_data(request, form.cleaned_data)

        if step_index < len(REGISTER_STEPS) - 1:
            request.session["register_step_index"] = step_index + 1
            next_step = REGISTER_STEPS[step_index + 1]
            next_form = next_step["form_class"](initial=get_register_session_data(request))
            return render(request, self.template_name, build_register_context(request, next_form))

        data = get_register_session_data(request)
        user = User(
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            email=data.get("email", ""),
            username=data.get("email", ""),
            phone_number=data.get("phone_number", ""),
            role=User.Role.USER,
            security_question=data.get("security_question", ""),
        )
        user.set_password(data.get("password1"))
        user.set_security_answer(data.get("security_answer", ""))
        user.set_pin(data.get("pin", ""))
        user.save()
        clear_register_session(request)

        # Log the user in and immediately trigger the sequential MFA flow
        login(request, user)
        request.session["mfa_verified"] = False
        request.session["pending_mfa_user_id"] = str(user.id)
        queue = build_mfa_queue(user, is_signup=True)
        request.session["mfa_factor_queue"] = list(queue)
        request.session["mfa_all_steps"] = list(queue)
        request.session["mfa_total_steps"] = len(queue)

        messages.success(request, "Congratulations. Your account was created successfully. Please complete the verification steps to finish registration.")
        return set_next_factor(request, user)


class LoginView(View):
    template_name = "auth/login.html"

    def get(self, request):
        return render(request, self.template_name, {"form": EmailAuthenticationForm(request=request)})

    def post(self, request):
        submitted_email = request.POST.get("username", "").strip()
        ip_address = get_client_ip(request)
        user = User.objects.filter(email__iexact=submitted_email).first() if submitted_email else None

        if too_many_recent_failures(email=submitted_email, ip_address=ip_address):
            log_login_activity(
                request=request,
                email=submitted_email,
                status=LoginActivity.Status.LOCKED,
                user=user,
                detail="Login throttled because too many recent failures were detected.",
            )
            messages.error(request, "Too many recent login attempts. Please wait and try again.")
            return render(request, self.template_name, {"form": EmailAuthenticationForm(request=request, data=request.POST)})

        if user and user.is_locked:
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.LOCKED,
                user=user,
                detail=f"Account is locked until {timezone.localtime(user.locked_until):%Y-%m-%d %H:%M}.",
            )
            messages.error(request, "This account is temporarily locked. Please try again later.")
            return render(request, self.template_name, {"form": EmailAuthenticationForm(request=request, data=request.POST)})

        form = EmailAuthenticationForm(request=request, data=request.POST)
        if not form.is_valid():
            if user:
                user.failed_login_count += 1
                update_fields = ["failed_login_count"]
                if user.failed_login_count >= settings.LOGIN_RATE_LIMIT_ATTEMPTS:
                    user.locked_until = timezone.now() + timedelta(minutes=settings.ACCOUNT_LOCK_MINUTES)
                    update_fields.append("locked_until")
                user.save(update_fields=update_fields)
            log_login_activity(
                request=request,
                email=submitted_email,
                status=LoginActivity.Status.FAILED_PASSWORD,
                user=user,
                detail="Password authentication failed.",
            )
            if user and user.is_locked:
                messages.error(request, f"This account is now locked for {settings.ACCOUNT_LOCK_MINUTES} minutes.")
            return render(request, self.template_name, {"form": form})

        user = form.get_user()
        if user.failed_login_count or user.locked_until:
            user.failed_login_count = 0
            user.locked_until = None
            user.save(update_fields=["failed_login_count", "locked_until"])

        trusted_device = get_trusted_device(request, user)
        unusual_login = is_unusual_login(
            user=user,
            ip_address=ip_address,
            device_name=describe_device(request.META.get("HTTP_USER_AGENT", "")[:500]),
            trusted_device=trusted_device,
        )
        login(request, user)
        request.session["mfa_verified"] = False
        request.session["pending_mfa_user_id"] = str(user.id)
        queue = build_mfa_queue(user, is_signup=False)
        request.session["mfa_factor_queue"] = list(queue)
        request.session["mfa_all_steps"] = list(queue)
        request.session["mfa_total_steps"] = len(queue)
        request.session["trusted_device_recognized"] = bool(trusted_device)
        request.session["unusual_login_detected"] = unusual_login
        if unusual_login:
            messages.warning(request, "New device or network detected. Extra care is recommended for this login.")
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
        if factor == "TEXT_CAPTCHA":
            return redirect("accounts:verify-text-captcha")
        if factor == "TOTP":
            return redirect("accounts:verify-totp")
        if factor == "QUESTION_SETUP":
            return redirect("accounts:verify-question-setup")
        if factor == "QUESTION":
            return redirect("accounts:verify-question")
        if factor == "PIN_SETUP":
            return redirect("accounts:verify-pin-setup")
        if factor == "VOICE_SETUP":
            return redirect("accounts:verify-voice-setup")
        if factor == "VOICE":
            return redirect("accounts:verify-voice")
        if factor == "PASSKEY":
            return redirect("accounts:verify-passkey")
        if factor == "PASSKEY_SETUP":
            return redirect("accounts:verify-passkey-setup")
        if factor == "TOTP_SETUP":
            return redirect("accounts:verify-totp-setup")
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
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading=f"Step {request.session.get('mfa_total_steps', 1) - len(request.session.get('mfa_factor_queue', []))} of {request.session.get('mfa_total_steps', 1)}: enter the code sent to {masked_destination}.",
                ),
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
                    **build_mfa_page_context(
                        request,
                        heading="Verify Identity",
                        subheading=f"Enter the code sent to {self.mask_email(user.email) if factor == OTPChallenge.Factor.EMAIL else mask_phone_number(user.phone_number)}.",
                    ),
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
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading=f"Enter the code sent to {self.mask_email(user.email) if factor == OTPChallenge.Factor.EMAIL else mask_phone_number(user.phone_number)}.",
                ),
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
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": CaptchaVerificationForm(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Complete the human verification check to continue to the next MFA step.",
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = CaptchaVerificationForm(request.POST)
        if form.is_valid() and form.cleaned_data.get("captcha_checkbox", False):
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
        return render(request, self.template_name, {"form": form})


class ImageVerifyView(View):
    template_name = "auth/verify_image.html"

    def get_context(self, challenge, form=None):
        option_keys = challenge.get("option_keys", [])
        choices = [(key, IMAGE_ITEM_LIBRARY[key]["label"]) for key in option_keys]
        if form is None:
            form = ImageVerificationForm()
        form.fields["image_choices"].choices = choices
        return {
            "form": form,
            "prompt_label": challenge.get("target_label", ""),
            "image_options": [
                {"key": key, **IMAGE_ITEM_LIBRARY[key]}
                for key in option_keys
            ],
        }

    def get(self, request):
        user = get_pending_user(request)
        challenge = request.session.get("image_challenge")
        if not user or not challenge:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                **self.get_context(challenge),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading=f"Select every image that matches {challenge.get('target_label', '').lower()} to continue.",
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        challenge = request.session.get("image_challenge")
        if not user or not challenge:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = ImageVerificationForm(request.POST)
        form.fields["image_choices"].choices = [
            (key, IMAGE_ITEM_LIBRARY[key]["label"]) for key in challenge.get("option_keys", [])
        ]
        correct = set(challenge.get("correct_keys", []))
        if form.is_valid() and set(form.cleaned_data["image_choices"]) == correct:
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
        messages.error(request, "Incorrect selection. Please select all matching images and try again.")
        return render(
            request,
            self.template_name,
            {
                **self.get_context(challenge, form=form),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading=f"Select every image that matches {challenge.get('target_label', '').lower()} to continue.",
                ),
            },
        )
        return render(request, self.template_name, context)


class TextCaptchaVerifyView(View):
    template_name = "auth/verify_text_captcha.html"

    def get(self, request):
        user = get_pending_user(request)
        captcha_text = request.session.get("text_captcha")
        if not user or not captcha_text:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": TextCaptchaForm(),
                "captcha_text": captcha_text,
                **build_mfa_page_context(
                    request,
                    heading="Security Verification",
                    subheading="Type the characters shown in the box to prove you are a human."
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        captcha_text = request.session.get("text_captcha")
        if not user or not captcha_text:
            return redirect("accounts:login")
        
        form = TextCaptchaForm(request.POST)
        if form.is_valid() and form.cleaned_data["captcha_input"].upper() == captcha_text.upper():
            request.session.pop("text_captcha", None)
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail="Text captcha verification succeeded.",
            )
            return set_next_factor(request, user)
        
        log_login_activity(
            request=request,
            email=user.email,
            status=LoginActivity.Status.FAILED_OTP,
            user=user,
            detail="Text captcha verification failed.",
        )
        messages.error(request, "Invalid characters. Please try again.")
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "captcha_text": captcha_text,
                **build_mfa_page_context(request, heading="Security Verification", subheading="Invalid characters. Please try again."),
            },
        )


class PinVerifyView(View):
    template_name = "auth/verify_pin.html"

    def get_user(self, request):
        return get_pending_user(request)

    def get(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": PinVerificationForm(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Enter the security PIN you created during registration.",
                ),
            },
        )

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
        return render(
            request,
            self.template_name,
            {
                "form": form,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Enter the security PIN you created during registration.",
                ),
            },
        )


class PinSetupView(View):
    template_name = "auth/verify_pin_setup.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": PinSetupForm(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Create your security PIN to complete the full MFA setup for this account.",
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = PinSetupForm(request.POST)
        if form.is_valid():
            user.set_pin(form.cleaned_data["pin"])
            user.save(update_fields=["pin_hash"])
            log_login_activity(request=request, email=user.email, status=LoginActivity.Status.SUCCESS, user=user, detail="PIN setup completed during login.")
            messages.success(request, "Security PIN set successfully.")
            return set_next_factor(request, user)
        return render(
            request,
            self.template_name,
            {
                "form": form,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Create your security PIN to complete the full MFA setup for this account.",
                ),
            },
        )


class VoiceSetupView(View):
    template_name = "auth/verify_voice_setup.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        challenge_phrase = get_or_issue_voice_challenge(request, refresh=True)
        return render(
            request,
            self.template_name,
            {
                "form": VoiceSetupForm(initial={"spoken_phrase": challenge_phrase}),
                "challenge_phrase": challenge_phrase,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Speak the challenge phrase and record a clean sample so we can enroll a server-side biometric voice reference.",
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        challenge_phrase = get_or_issue_voice_challenge(request)
        form = VoiceSetupForm(request.POST, request.FILES)
        if form.is_valid():
            spoken_phrase = normalize_phrase(form.cleaned_data["spoken_phrase"])
            if not phrase_matches_expected(spoken_phrase, challenge_phrase):
                messages.error(request, "The spoken phrase did not match the challenge phrase. Please try again.")
                return render(
                    request,
                    self.template_name,
                    {
                        "form": form,
                        "challenge_phrase": challenge_phrase,
                        **build_mfa_page_context(
                            request,
                            heading="Verify Identity",
                            subheading="Speak the challenge phrase and record a clean sample so we can enroll a server-side biometric voice reference.",
                        ),
                    },
                )
            result = enroll_user_voice(user, form.cleaned_data["audio_file"], spoken_phrase)
            if not result["ok"]:
                messages.error(request, result["message"])
                return render(
                    request,
                    self.template_name,
                    {
                        "form": form,
                        "challenge_phrase": challenge_phrase,
                        "voice_quality": result.get("quality"),
                        **build_mfa_page_context(
                            request,
                            heading="Verify Identity",
                            subheading="Speak the challenge phrase and record a clean sample so we can enroll a server-side biometric voice reference.",
                        ),
                    },
                )
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail="Voice biometric profile enrolled successfully.",
            )
            request.session.pop("voice_challenge_phrase", None)
            request.session.pop("voice_challenge_issued_at", None)
            messages.success(request, "Voice biometric enrollment completed successfully.")
            return set_next_factor(request, user)
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "challenge_phrase": challenge_phrase,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Speak the challenge phrase and record a clean sample so we can enroll a server-side biometric voice reference.",
                ),
            },
        )


class VoiceVerifyView(View):
    template_name = "auth/verify_voice.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        challenge_phrase = get_or_issue_voice_challenge(request, refresh=True)
        return render(
            request,
            self.template_name,
            {
                "form": VoiceVerificationForm(initial={"spoken_phrase": challenge_phrase}),
                "expected_phrase": challenge_phrase,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Speak the live challenge phrase so we can compare your new recording against the enrolled server-side voice reference.",
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        challenge_phrase = get_or_issue_voice_challenge(request)
        form = VoiceVerificationForm(request.POST, request.FILES)
        if form.is_valid():
            spoken_phrase = normalize_phrase(form.cleaned_data["spoken_phrase"])
            if not phrase_matches_expected(spoken_phrase, challenge_phrase):
                log_login_activity(
                    request=request,
                    email=user.email,
                    status=LoginActivity.Status.FAILED_OTP,
                    user=user,
                    detail="Voice verification failed because the challenge phrase did not match.",
                )
                messages.error(request, "The spoken phrase did not match the challenge phrase. Please try again.")
                return render(
                    request,
                    self.template_name,
                    {
                        "form": form,
                        "expected_phrase": challenge_phrase,
                        **build_mfa_page_context(
                            request,
                            heading="Verify Identity",
                            subheading="Speak the live challenge phrase so we can compare your new recording against the enrolled server-side voice reference.",
                        ),
                    },
                )
            result = verify_user_voice(user, form.cleaned_data["audio_file"])
            if result["ok"]:
                log_login_activity(
                    request=request,
                    email=user.email,
                    status=LoginActivity.Status.SUCCESS,
                    user=user,
                    detail=f"Voice verification succeeded with score {result.get('score', 'n/a')}.",
                )
                request.session.pop("voice_challenge_phrase", None)
                request.session.pop("voice_challenge_issued_at", None)
                messages.success(request, "Voice verification succeeded.")
                return set_next_factor(request, user)
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.FAILED_OTP,
                user=user,
                detail=f"Voice verification failed. {result.get('message', 'No detail')} Score: {result.get('score', 'n/a')}.",
            )
            messages.error(request, result.get("message", "Voice verification failed. Please record again and speak the challenge phrase clearly."))
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "expected_phrase": challenge_phrase,
                "voice_quality": result.get("quality") if "result" in locals() else None,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Speak the live challenge phrase so we can compare your new recording against the enrolled server-side voice reference.",
                ),
            },
        )


class SecurityQuestionVerifyView(View):
    template_name = "auth/verify_question.html"

    def get_user(self, request):
        return get_pending_user(request)

    def get(self, request):
        user = self.get_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": SecurityQuestionForm(),
                "question": user.get_security_question_display(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Answer your saved security question to continue.",
                ),
            },
        )

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
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "question": user.get_security_question_display(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Answer your saved security question to continue.",
                ),
            },
        )


class SecurityQuestionSetupView(View):
    template_name = "auth/verify_question_setup.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": SecurityQuestionSetupForm(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Set your security question and answer so future logins can use the full MFA chain.",
                ),
            },
        )

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        form = SecurityQuestionSetupForm(request.POST)
        if form.is_valid():
            user.security_question = form.cleaned_data["security_question"]
            user.set_security_answer(form.cleaned_data["security_answer"])
            user.save(update_fields=["security_question", "security_answer_hash"])
            log_login_activity(request=request, email=user.email, status=LoginActivity.Status.SUCCESS, user=user, detail="Security question setup completed during login.")
            messages.success(request, "Security question saved successfully.")
            return set_next_factor(request, user)
        return render(
            request,
            self.template_name,
            {
                "form": form,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Set your security question and answer so future logins can use the full MFA chain.",
                ),
            },
        )


class TOTPSetupView(View):
    template_name = "auth/setup_totp.html"

    def get(self, request):
        if not request.user.is_authenticated or not request.session.get("mfa_verified"):
            messages.error(request, "Please complete multi-factor verification first.")
            return redirect("accounts:login")
        user = request.user
        secret = user.ensure_totp_secret()
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
        secret = user.ensure_totp_secret()
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
                "secret": secret,
                "otpauth_uri": user.get_totp_uri(),
                "qr_code_data_uri": generate_totp_qr_data_uri(user.get_totp_uri()),
                "form": form,
                "totp_enabled": user.totp_enabled,
            },
        )


class TOTPSetupMFAView(View):
    """TOTP setup that runs inside the MFA queue during signup (no mfa_verified required)."""

    template_name = "auth/verify_totp_setup.html"

    def _context(self, request, user, form=None):
        return {
            "secret": user.totp_secret,
            "otpauth_uri": user.get_totp_uri(),
            "qr_code_data_uri": generate_totp_qr_data_uri(user.get_totp_uri()),
            "form": form or TOTPVerificationForm(),
            **build_mfa_page_context(
                request,
                heading="Verify Identity",
                subheading="Set up your authenticator app, then enter the current 6-digit code to finish this step.",
            ),
        }

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        user.ensure_totp_secret()
        return render(request, self.template_name, self._context(request, user))

    def post(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        user.ensure_totp_secret()
        form = TOTPVerificationForm(request.POST)
        if form.is_valid() and user.verify_totp(form.cleaned_data["otp"]):
            user.totp_enabled = True
            user.save(update_fields=["totp_secret", "totp_enabled"])
            log_login_activity(
                request=request,
                email=user.email,
                status=LoginActivity.Status.SUCCESS,
                user=user,
                detail="TOTP set up and verified during registration.",
            )
            messages.success(request, "Authenticator app enabled successfully.")
            return set_next_factor(request, user)
        messages.error(request, "Invalid code. Please try again.")
        return render(request, self.template_name, self._context(request, user, form))


class TOTPVerifyView(View):
    template_name = "auth/verify_totp.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "form": TOTPVerificationForm(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Enter the current 6-digit code from your authenticator app.",
                ),
            },
        )

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
        return render(
            request,
            self.template_name,
            {
                "form": form,
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Enter the current 6-digit code from your authenticator app.",
                ),
            },
        )


class PasskeyVerifyView(View):
    template_name = "auth/verify_passkey.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your login session expired. Please sign in again.")
            return redirect("accounts:login")
        return render(
            request,
            self.template_name,
            {
                "passkey_count": user.passkeys.count(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Use face unlock, fingerprint, Windows Hello, or your saved passkey on this device.",
                ),
            },
        )


class PasskeySetupMFAView(View):
    template_name = "auth/verify_passkey_setup.html"

    def get(self, request):
        user = get_pending_user(request)
        if not user:
            messages.error(request, "Your registration session expired. Please sign up again.")
            return redirect("accounts:register")
        return render(
            request,
            self.template_name,
            {
                "passkey_count": user.passkeys.count(),
                **build_mfa_page_context(
                    request,
                    heading="Verify Identity",
                    subheading="Create a passkey on this device to finish registration and unlock the full login flow.",
                ),
            },
        )


@method_decorator(require_POST, name="dispatch")
class PasskeyRegistrationOptionsView(View):
    def post(self, request):
        try:
            is_signup_setup = request.session.get("current_mfa_factor") == "PASSKEY_SETUP"
            acting_user = get_pending_user(request) if is_signup_setup else request.user
            if not acting_user or not acting_user.is_authenticated:
                if not is_signup_setup:
                    acting_user = request.user if request.user.is_authenticated else None
            if not acting_user or (not is_signup_setup and not request.session.get("mfa_verified")):
                return JsonResponse({"error": "Authentication required."}, status=403)

            try:
                exclude_credentials = [
                    PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id))
                    for item in acting_user.passkeys.all()
                ]
            except Exception as e:
                exclude_credentials = []

            options = generate_registration_options(
                rp_id=get_webauthn_rp_id(request),
                rp_name=settings.WEBAUTHN_RP_NAME,
                user_name=acting_user.email,
                user_id=str(acting_user.id).encode("utf-8"),
                user_display_name=acting_user.get_full_name() or acting_user.email,
                exclude_credentials=exclude_credentials,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.PREFERRED,
                ),
            )
            request.session["webauthn_registration_challenge"] = encode_challenge(options.challenge)
            return JsonResponse(json.loads(options_to_json(options)))
        except Exception as e:
            return JsonResponse({"error": f"Failed to generate registration options: {str(e)}"}, status=500)


@method_decorator(require_POST, name="dispatch")
class PasskeyRegistrationVerifyView(View):
    def post(self, request):
        try:
            is_signup_setup = request.session.get("current_mfa_factor") == "PASSKEY_SETUP"
            acting_user = get_pending_user(request) if is_signup_setup else request.user
            if not acting_user or (not is_signup_setup and not request.session.get("mfa_verified")):
                return JsonResponse({"error": "Authentication required."}, status=403)
            challenge = request.session.get("webauthn_registration_challenge")
            if not challenge:
                return JsonResponse({"error": "Registration challenge expired."}, status=400)
            
            try:
                credential = json.loads(request.body.decode("utf-8"))
            except json.JSONDecodeError:
                return JsonResponse({"error": "Invalid JSON in request body."}, status=400)
            
            try:
                verification = verify_registration_response(
                    credential=credential,
                    expected_challenge=decode_challenge(challenge),
                    expected_rp_id=get_webauthn_rp_id(request),
                    expected_origin=get_webauthn_origin(request),
                )
            except Exception as exc:
                return JsonResponse({"error": f"Verification failed: {str(exc)}"}, status=400)

            label = credential.get("friendlyName") or f"Passkey {acting_user.passkeys.count() + 1}"
            PasskeyCredential.objects.create(
                user=acting_user,
                name=label,
                credential_id=bytes_to_base64url(verification.credential_id),
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                transports=credential.get("response", {}).get("transports", []),
            )
            request.session.pop("webauthn_registration_challenge", None)
            if is_signup_setup:
                response = set_next_factor(request, acting_user)
                return JsonResponse({"status": "ok", "redirect_url": response.url})
            return JsonResponse({"status": "ok"})
        except Exception as e:
            return JsonResponse({"error": f"Registration error: {str(e)}"}, status=500)


@method_decorator(require_POST, name="dispatch")
class PasskeyAuthenticationOptionsView(View):
    def post(self, request):
        try:
            user = get_pending_user(request)
            if not user:
                return JsonResponse({"error": "Authentication required."}, status=403)
            credentials = list(user.passkeys.all())
            if not credentials:
                return JsonResponse({"error": "No passkeys registered."}, status=400)
            
            try:
                allow_credentials = [
                    PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id))
                    for item in credentials
                ]
            except Exception as e:
                return JsonResponse({"error": f"Failed to process passkeys: {str(e)}"}, status=400)
            
            options = generate_authentication_options(
                rp_id=get_webauthn_rp_id(request),
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.PREFERRED,
            )
            request.session["webauthn_authentication_challenge"] = encode_challenge(options.challenge)
            return JsonResponse(json.loads(options_to_json(options)))
        except Exception as e:
            return JsonResponse({"error": f"Failed to generate authentication options: {str(e)}"}, status=500)


@method_decorator(require_POST, name="dispatch")
class PasskeyAuthenticationVerifyView(View):
    def post(self, request):
        try:
            user = get_pending_user(request)
            if not user:
                return JsonResponse({"error": "Authentication required."}, status=403)
            challenge = request.session.get("webauthn_authentication_challenge")
            if not challenge:
                return JsonResponse({"error": "Authentication challenge expired."}, status=400)
            
            try:
                credential = json.loads(request.body.decode("utf-8"))
            except json.JSONDecodeError:
                return JsonResponse({"error": "Invalid JSON in request body."}, status=400)
            
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
                    expected_rp_id=get_webauthn_rp_id(request),
                    expected_origin=get_webauthn_origin(request),
                    credential_public_key=bytes(stored.public_key),
                    credential_current_sign_count=stored.sign_count,
                )
            except Exception as exc:
                return JsonResponse({"error": f"Verification failed: {str(exc)}"}, status=400)

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
        except Exception as e:
            return JsonResponse({"error": f"Authentication error: {str(e)}"}, status=500)


@mfa_verified_required
def dashboard(request):
    if request.user.role == User.Role.ADMIN:
        return redirect("accounts:admin-dashboard")
    return redirect("accounts:user-dashboard")


def build_login_chart(queryset, days=7):
    today = timezone.localdate()
    start_day = today - timedelta(days=days - 1)
    counts_by_day = {}
    daily_counts = (
        queryset.filter(
            status=LoginActivity.Status.SUCCESS,
            created_at__date__gte=start_day,
            created_at__date__lte=today,
        )
        .annotate(login_day=TruncDate("created_at"))
        .values("login_day")
        .annotate(total=models.Count("id"))
    )
    for item in daily_counts:
        counts_by_day[item["login_day"].isoformat()] = item["total"]

    chart = []
    peak = max(counts_by_day.values(), default=0)
    for offset in range(days):
        day = start_day + timedelta(days=offset)
        count = counts_by_day.get(day.isoformat(), 0)
        height = round((count / peak) * 100) if peak else 0
        chart.append(
            {
                "label": day.strftime("%b %d"),
                "short_label": day.strftime("%a"),
                "count": count,
                "height": max(6, height) if count else 0,
            }
        )
    return chart


@admin_required
def admin_dashboard(request):
    activities = LoginActivity.objects.select_related("user").order_by("-created_at")[:10]
    user_count = User.objects.count()
    admin_count = User.objects.filter(role=User.Role.ADMIN).count()
    login_chart = build_login_chart(LoginActivity.objects.all())
    context = {
        "user_count": user_count,
        "admin_count": admin_count,
        "standard_user_count": max(0, user_count - admin_count),
        "locked_user_count": User.objects.filter(locked_until__gt=timezone.now()).count(),
        "unusual_event_count": LoginActivity.objects.filter(is_unusual=True).count(),
        "locked_event_count": LoginActivity.objects.filter(status=LoginActivity.Status.LOCKED).count(),
        "login_chart": login_chart,
        "login_chart_total": sum(item["count"] for item in login_chart),
        "login_chart_peak": max((item["count"] for item in login_chart), default=0),
        "activities": activities,
    }
    return render(request, "dashboard/admin_dashboard.html", context)


@mfa_verified_required
def profile(request):
    from .forms import ProfilePasswordForm, ProfileUpdateForm

    profile_form = ProfileUpdateForm(instance=request.user)
    password_form = ProfilePasswordForm()
    profile_errors = None
    password_errors = None
    profile_success = False
    password_success = False

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "update_profile":
            profile_form = ProfileUpdateForm(request.POST, instance=request.user)
            if profile_form.is_valid():
                profile_form.save()
                messages.success(request, "Profile updated successfully.")
                profile_success = True
            else:
                profile_errors = profile_form.errors
        elif action == "change_password":
            password_form = ProfilePasswordForm(request.POST)
            if password_form.is_valid():
                current_password = password_form.cleaned_data["current_password"]
                if request.user.check_password(current_password):
                    request.user.set_password(password_form.cleaned_data["new_password"])
                    request.user.save(update_fields=["password"])
                    update_session_auth_hash(request, request.user)
                    messages.success(request, "Password changed successfully.")
                    password_success = True
                    password_form = ProfilePasswordForm()
                else:
                    password_form.add_error("current_password", "Current password is incorrect.")
                    password_errors = password_form.errors
            else:
                password_errors = password_form.errors

    return render(request, "dashboard/profile.html", {
        "profile_form": profile_form,
        "password_form": password_form,
        "profile_errors": profile_errors,
        "password_errors": password_errors,
        "profile_success": profile_success,
        "password_success": password_success,
    })


@admin_required
def admin_logs(request):
    activities = LoginActivity.objects.select_related("user").order_by("-created_at")
    summary = activities.aggregate(
        success_count=models.Count("id", filter=models.Q(status=LoginActivity.Status.SUCCESS)),
        failed_password_count=models.Count("id", filter=models.Q(status=LoginActivity.Status.FAILED_PASSWORD)),
        failed_otp_count=models.Count("id", filter=models.Q(status=LoginActivity.Status.FAILED_OTP)),
        unusual_count=models.Count("id", filter=models.Q(is_unusual=True)),
        lockout_count=models.Count("id", filter=models.Q(status=LoginActivity.Status.LOCKED)),
    )
    paginator = Paginator(activities, 25)
    page_obj = paginator.get_page(request.GET.get("page"))
    failed_count = summary["failed_password_count"] + summary["failed_otp_count"]
    storage_capacity_kb = 10240
    storage_used_kb = min(storage_capacity_kb, max(1 if paginator.count else 0, round(paginator.count * 2.1)))
    storage_percent = round((storage_used_kb / storage_capacity_kb) * 100) if storage_capacity_kb else 0
    return render(
        request,
        "dashboard/admin_logs.html",
        {
            "page_obj": page_obj,
            "activity_count": paginator.count,
            "success_count": summary["success_count"],
            "failed_count": failed_count,
            "unusual_count": summary["unusual_count"],
            "lockout_count": summary["lockout_count"],
            "storage_used_kb": storage_used_kb,
            "storage_capacity_mb": round(storage_capacity_kb / 1024),
            "storage_percent": storage_percent,
        },
    )


@mfa_verified_required
def user_dashboard(request):
    """Standard user dashboard showing recent login activity."""
    activities = LoginActivity.objects.filter(user=request.user).order_by("-created_at")
    paginator = Paginator(activities, 10)
    page_obj = paginator.get_page(request.GET.get("page"))
    recent_alerts = activities.filter(is_unusual=True)[:5]
    trusted_devices = request.user.trusted_devices.all()[:5]
    login_chart = build_login_chart(LoginActivity.objects.filter(user=request.user))
    return render(
        request,
        "dashboard/user_dashboard.html",
        {
            "page_obj": page_obj,
            "recent_alerts": recent_alerts,
            "trusted_devices": trusted_devices,
            "login_chart": login_chart,
            "login_chart_total": sum(item["count"] for item in login_chart),
            "login_chart_peak": max((item["count"] for item in login_chart), default=0),
        },
    )

class AppLogoutView(LogoutView):
    """Custom logout view to handle session clearing and success messages."""
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            messages.success(request, "You have been successfully logged out.")
        return super().dispatch(request, *args, **kwargs)


class PasswordResetRequestView(View):
    template_name = "auth/password_reset_request.html"

    def get(self, request):
        return render(request, self.template_name, {"form": PasswordResetRequestForm()})

    def post(self, request):
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            user = User.objects.filter(email__iexact=email).first()
            if user:
                # Issue an OTP for password reset
                try:
                    issue_otp(user, OTPChallenge.Factor.EMAIL)
                    messages.success(request, "A password reset code has been sent to your email address.")
                    request.session["password_reset_email"] = user.email
                    return redirect("accounts:password-reset-otp-verify")
                except Exception:
                    messages.error(request, "Could not send password reset email. Please try again later.")
            else:
                messages.error(request, "No account found with that email address.")
        return render(request, self.template_name, {"form": form})


class PasswordResetOTPVerifyView(View):
    template_name = "auth/password_reset_otp_verify.html"

    def get(self, request):
        email = request.session.get("password_reset_email")
        if not email:
            messages.error(request, "Please request a password reset first.")
            return redirect("accounts:password-reset-request")
        
        user = User.objects.filter(email__iexact=email).first()
        if not user:
            messages.error(request, "User not found for password reset.")
            return redirect("accounts:password-reset-request")

        latest_otp = user.otp_challenges.filter(
            consumed_at__isnull=True, factor=OTPChallenge.Factor.EMAIL
        ).order_by("-created_at").first()
        
        cooldown = 0
        if latest_otp:
            cooldown = max(
                0,
                settings.OTP_RESEND_COOLDOWN_SECONDS - int((timezone.now() - latest_otp.created_at).total_seconds()),
            )

        return render(
            request,
            self.template_name,
            {
                "form": PasswordResetOTPForm(),
                "masked_email": OTPVerifyView.mask_email(email),
                "otp_ttl": max(1, settings.OTP_TTL_SECONDS // 60),
                "resend_cooldown": cooldown,
            },
        )

    def post(self, request):
        email = request.session.get("password_reset_email")
        if not email:
            messages.error(request, "Please request a password reset first.")
            return redirect("accounts:password-reset-request")

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            messages.error(request, "User not found for password reset.")
            return redirect("accounts:password-reset-request")

        form = PasswordResetOTPForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "masked_email": OTPVerifyView.mask_email(email),
                    "otp_ttl": max(1, settings.OTP_TTL_SECONDS // 60),
                    "resend_cooldown": 0,
                },
            )

        challenge = user.otp_challenges.filter(
            consumed_at__isnull=True, factor=OTPChallenge.Factor.EMAIL
        ).order_by("-created_at").first()

        if not challenge:
            messages.error(request, "No active OTP found. Please request a new password reset.")
            return redirect("accounts:password-reset-request")

        if challenge.verify(form.cleaned_data["otp"]):
            challenge.mark_consumed()
            request.session["password_reset_otp_verified"] = True
            messages.success(request, "OTP verified. You can now set a new password.")
            return redirect("accounts:password-reset-confirm")
        
        if challenge.attempts >= settings.OTP_MAX_ATTEMPTS or challenge.is_expired:
            challenge.mark_consumed()
            messages.error(request, "OTP expired or maximum attempts reached. Please request a new password reset.")
            return redirect("accounts:password-reset-request")

        messages.error(request, "Invalid OTP. Please try again.")
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "masked_email": OTPVerifyView.mask_email(email),
                "otp_ttl": max(1, settings.OTP_TTL_SECONDS // 60),
                "resend_cooldown": 0,
            },
        )


class PasswordResetConfirmView(View):
    template_name = "auth/password_reset_confirm.html"

    def get(self, request):
        if not request.session.get("password_reset_otp_verified"):
            messages.error(request, "Please verify your OTP first.")
            return redirect("accounts:password-reset-request")
        return render(
            request,
            self.template_name,
            {
                "form": SetPasswordForm(),
                "email": request.session.get("password_reset_email", ""),
            },
        )

    def post(self, request):
        if not request.session.get("password_reset_otp_verified"):
            messages.error(request, "Please verify your OTP first.")
            return redirect("accounts:password-reset-request")

        email = request.session.get("password_reset_email")
        user = User.objects.filter(email__iexact=email).first()
        if not user:
            messages.error(request, "User not found for password reset.")
            return redirect("accounts:password-reset-request")

        form = SetPasswordForm(request.POST)
        if form.is_valid():
            user.set_password(form.cleaned_data["new_password"])
            user.save()
            messages.success(request, "Your password has been reset successfully. You can now log in.")
            request.session.pop("password_reset_email", None)
            request.session.pop("password_reset_otp_verified", None)
            return redirect("accounts:login")
        return render(request, self.template_name, {"form": form, "email": email})

@mfa_verified_required
def document_list(request):
    """View to list and upload documents for the authenticated user."""
    if request.method == "POST":
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.user = request.user
            document.save()
            messages.success(request, "Document uploaded successfully and scanned for security.")
            return redirect("accounts:document-dashboard")
    else:
        form = DocumentUploadForm()
    documents = request.user.documents.all()
    return render(request, "dashboard/documents.html", {"documents": documents, "form": form})

@mfa_verified_required
def serve_document(request, document_id):
    """Securely serve a document after MFA verification."""
    document = get_object_or_404(Document, id=document_id, user=request.user)
    try:
        # Open the file in binary mode and let FileResponse stream it to the browser
        response = FileResponse(document.file.open('rb'))
        return response
    except FileNotFoundError:
        raise Http404("Document file not found on the server.")

@mfa_verified_required
@require_POST
def delete_document(request, document_id):
    """Securely delete a document and its associated file."""
    document = get_object_or_404(Document, id=document_id, user=request.user)
    document.file.delete(save=False)
    document.delete()
    messages.success(request, "Document deleted successfully.")
    return redirect("accounts:document-dashboard")
