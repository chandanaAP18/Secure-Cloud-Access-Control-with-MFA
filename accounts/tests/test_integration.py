import io
import math
import wave

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import OTPChallenge, TrustedDevice
from accounts.voice_biometrics import enroll_user_voice
from auditlog.models import LoginActivity
import pyotp

User = get_user_model()


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    VOICE_BIOMETRIC_BACKEND="mock",
)
class LoginFlowIntegrationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="member@example.com",
            password="VeryStrongPassword123!",
            first_name="Member",
            phone_number="9876543210",
            security_question=User.SecurityQuestion.PET,
        )
        self.user.set_security_answer("bruno")
        self.user.set_pin("1234")
        enroll_user_voice(self.user, self.voice_sample(), "secure cloud access token")
        self.user.ensure_totp_secret()
        self.user.totp_enabled = True
        self.user.save(update_fields=["security_answer_hash", "pin_hash", "totp_secret", "totp_enabled"])

    def complete_image_challenge(self):
        challenge = self.client.session["image_challenge"]
        return self.client.post(
            reverse("accounts:verify-image"),
            {"image_choices": challenge["correct_keys"]},
            follow=True,
        )

    def voice_sample(self, name="voice.wav"):
        buffer = io.BytesIO()
        with wave.open(buffer, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(16000)
            frames = bytearray()
            for index in range(16000 * 3):
                value = int(12000 * math.sin(2 * math.pi * 220 * index / 16000))
                frames.extend(value.to_bytes(2, byteorder="little", signed=True))
            wav_file.writeframes(bytes(frames))
        return SimpleUploadedFile(name, buffer.getvalue(), content_type="audio/wav")

    def test_login_runs_through_sequential_factors(self):
        response = self.client.post(
            reverse("accounts:login"),
            {"username": self.user.email, "password": "VeryStrongPassword123!"},
            follow=True,
        )

        self.assertRedirects(response, reverse("accounts:verify-otp"))
        self.assertEqual(len(mail.outbox), 1)
        email_otp = OTPChallenge.objects.filter(user=self.user, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        email_otp.code_hash = OTPChallenge.hash_code("123456")
        email_otp.save(update_fields=["code_hash"])

        response = self.client.post(reverse("accounts:verify-otp"), {"otp": "123456"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-captcha"))

        response = self.client.post(reverse("accounts:verify-captcha"), {"captcha_checkbox": True}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-image"))

        response = self.complete_image_challenge()
        self.assertRedirects(response, reverse("accounts:verify-text-captcha"))

        text_captcha = self.client.session["text_captcha"]
        response = self.client.post(reverse("accounts:verify-text-captcha"), {"captcha_input": text_captcha}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-question"))

        response = self.client.post(reverse("accounts:verify-question"), {"answer": "bruno"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-pin"))

        response = self.client.post(reverse("accounts:verify-pin"), {"pin": "1234"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-voice"))
        voice_phrase = self.client.session["voice_challenge_phrase"]

        response = self.client.post(
            reverse("accounts:verify-voice"),
            {"spoken_phrase": voice_phrase, "audio_file": self.voice_sample()},
            follow=True,
        )
        self.assertRedirects(response, reverse("accounts:verify-totp"))

        totp_code = pyotp.TOTP(self.user.totp_secret).now()
        response = self.client.post(reverse("accounts:verify-totp"), {"otp": totp_code}, follow=True)
        self.assertRedirects(response, reverse("accounts:user-dashboard"))

        self.assertEqual(LoginActivity.objects.filter(status=LoginActivity.Status.OTP_SENT).count(), 1)
        self.assertGreaterEqual(LoginActivity.objects.filter(status=LoginActivity.Status.SUCCESS).count(), 6)
        self.assertIn("text/html", [alt[1] for alt in mail.outbox[0].alternatives])
        self.assertEqual(TrustedDevice.objects.filter(user=self.user).count(), 1)

    def test_signup_runs_through_same_mfa_family(self):
        response = self.client.post(
            reverse("accounts:register"),
            {
                "first_name": "New",
                "last_name": "Member",
                "email": "newmember@example.com",
                "phone_number": "",
            },
            follow=True,
        )
        self.assertContains(response, "Create your password")

        response = self.client.post(
            reverse("accounts:register"),
            {
                "password1": "VeryStrongPassword123!",
                "password2": "VeryStrongPassword123!",
            },
            follow=True,
        )
        self.assertContains(response, "Set your recovery factors")

        response = self.client.post(
            reverse("accounts:register"),
            {
                "security_question": User.SecurityQuestion.PET,
                "security_answer": "nova",
                "pin": "5678",
                "captcha_checkbox": True,
            },
            follow=True,
        )

        self.assertRedirects(response, reverse("accounts:verify-otp"))
        self.assertEqual(len(mail.outbox), 1)

        user = User.objects.get(email="newmember@example.com")
        email_otp = OTPChallenge.objects.filter(user=user, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        email_otp.code_hash = OTPChallenge.hash_code("123456")
        email_otp.save(update_fields=["code_hash"])

        response = self.client.post(reverse("accounts:verify-otp"), {"otp": "123456"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-captcha"))

        response = self.client.post(reverse("accounts:verify-captcha"), {"captcha_checkbox": True}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-image"))

        response = self.complete_image_challenge()
        self.assertRedirects(response, reverse("accounts:verify-text-captcha"))

        text_captcha = self.client.session["text_captcha"]
        response = self.client.post(reverse("accounts:verify-text-captcha"), {"captcha_input": text_captcha}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-question"))

        response = self.client.post(reverse("accounts:verify-question"), {"answer": "nova"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-pin"))

        response = self.client.post(reverse("accounts:verify-pin"), {"pin": "5678"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-voice-setup"))
        voice_phrase = self.client.session["voice_challenge_phrase"]

        response = self.client.post(
            reverse("accounts:verify-voice-setup"),
            {"spoken_phrase": voice_phrase, "audio_file": self.voice_sample()},
            follow=True,
        )
        self.assertRedirects(response, reverse("accounts:verify-totp-setup"))

        user.refresh_from_db()
        totp_code = pyotp.TOTP(user.totp_secret).now()
        response = self.client.post(reverse("accounts:verify-totp-setup"), {"otp": totp_code}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-passkey-setup"))

        user.refresh_from_db()
        self.assertTrue(user.totp_enabled)
        self.assertTrue(user.voice_enabled)

    def test_user_can_enable_totp_from_dashboard(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()

        response = self.client.get(reverse("accounts:setup-totp"))
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        code = pyotp.TOTP(self.user.totp_secret).now()
        response = self.client.post(reverse("accounts:setup-totp"), {"otp": code}, follow=True)
        self.user.refresh_from_db()
        self.assertTrue(self.user.totp_enabled)

    def test_login_for_incomplete_account_redirects_into_setup_steps(self):
        legacy_user = User.objects.create_user(
            email="legacy@example.com",
            password="VeryStrongPassword123!",
            first_name="Legacy",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {"username": legacy_user.email, "password": "VeryStrongPassword123!"},
            follow=True,
        )

        self.assertRedirects(response, reverse("accounts:verify-otp"))
        email_otp = OTPChallenge.objects.filter(user=legacy_user, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        email_otp.code_hash = OTPChallenge.hash_code("123456")
        email_otp.save(update_fields=["code_hash"])

        response = self.client.post(reverse("accounts:verify-otp"), {"otp": "123456"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-captcha"))

        response = self.client.post(reverse("accounts:verify-captcha"), {"captcha_checkbox": True}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-image"))

        response = self.complete_image_challenge()
        self.assertRedirects(response, reverse("accounts:verify-text-captcha"))

        text_captcha = self.client.session["text_captcha"]
        response = self.client.post(reverse("accounts:verify-text-captcha"), {"captcha_input": text_captcha}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-question-setup"))

    def test_login_incomplete_account_reaches_passkey_setup_after_totp_setup(self):
        legacy_user = User.objects.create_user(
            email="legacy-passkey@example.com",
            password="VeryStrongPassword123!",
            first_name="Legacy",
        )

        response = self.client.post(
            reverse("accounts:login"),
            {"username": legacy_user.email, "password": "VeryStrongPassword123!"},
            follow=True,
        )
        self.assertRedirects(response, reverse("accounts:verify-otp"))

        email_otp = OTPChallenge.objects.filter(user=legacy_user, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        email_otp.code_hash = OTPChallenge.hash_code("123456")
        email_otp.save(update_fields=["code_hash"])

        response = self.client.post(reverse("accounts:verify-otp"), {"otp": "123456"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-captcha"))
        response = self.client.post(reverse("accounts:verify-captcha"), {"captcha_checkbox": True}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-image"))
        response = self.complete_image_challenge()
        self.assertRedirects(response, reverse("accounts:verify-text-captcha"))
        text_captcha = self.client.session["text_captcha"]
        response = self.client.post(reverse("accounts:verify-text-captcha"), {"captcha_input": text_captcha}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-question-setup"))
        response = self.client.post(
            reverse("accounts:verify-question-setup"),
            {
                "security_question": User.SecurityQuestion.PET,
                "security_answer": "nova",
            },
            follow=True,
        )
        self.assertRedirects(response, reverse("accounts:verify-pin-setup"))
        response = self.client.post(reverse("accounts:verify-pin-setup"), {"pin": "5678"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-voice-setup"))
        voice_phrase = self.client.session["voice_challenge_phrase"]

        response = self.client.post(
            reverse("accounts:verify-voice-setup"),
            {"spoken_phrase": voice_phrase, "audio_file": self.voice_sample()},
            follow=True,
        )
        self.assertRedirects(response, reverse("accounts:verify-totp-setup"))

        legacy_user.refresh_from_db()
        totp_code = pyotp.TOTP(legacy_user.totp_secret).now()
        response = self.client.post(reverse("accounts:verify-totp-setup"), {"otp": totp_code}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-passkey-setup"))

    @override_settings(LOGIN_RATE_LIMIT_ATTEMPTS=3, ACCOUNT_LOCK_MINUTES=15)
    def test_account_is_locked_after_repeated_failed_password_attempts(self):
        login_url = reverse("accounts:login")

        for _ in range(3):
            self.client.post(login_url, {"username": self.user.email, "password": "wrong-password"})

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_locked)
        self.assertTrue(LoginActivity.objects.filter(user=self.user, status=LoginActivity.Status.FAILED_PASSWORD).count() >= 3)

        response = self.client.post(login_url, {"username": self.user.email, "password": "VeryStrongPassword123!"}, follow=True)

        self.assertContains(response, "Too many recent login attempts", status_code=200)
        self.assertTrue(LoginActivity.objects.filter(user=self.user, status=LoginActivity.Status.LOCKED).exists())
