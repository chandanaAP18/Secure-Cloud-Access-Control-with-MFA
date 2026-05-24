from django.contrib.auth import get_user_model
from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import OTPChallenge, TrustedDevice
from auditlog.models import LoginActivity
import pyotp

import io
import math
import wave
from django.core.files.uploadedfile import SimpleUploadedFile

User = get_user_model()


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    VOICE_BIOMETRIC_BACKEND="mock",
)
class RoleBasedSystemTests(TestCase):
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

    def complete_mfa_login(self, email, password, email_otp="654321", totp_code=None, answer="gm", pin="4321"):
        self.client.post(reverse("accounts:login"), {"username": email, "password": password})
        challenge = OTPChallenge.objects.filter(user__email=email, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        challenge.code_hash = OTPChallenge.hash_code(email_otp)
        challenge.save(update_fields=["code_hash"])
        self.client.post(reverse("accounts:verify-otp"), {"otp": email_otp}, follow=True)
        self.client.post(reverse("accounts:verify-captcha"), {"captcha_checkbox": True}, follow=True)
        image_challenge = self.client.session["image_challenge"]
        self.client.post(reverse("accounts:verify-image"), {"image_choices": image_challenge["correct_keys"]}, follow=True)
        text_captcha = self.client.session["text_captcha"]
        self.client.post(reverse("accounts:verify-text-captcha"), {"captcha_input": text_captcha}, follow=True)
        self.client.post(reverse("accounts:verify-question"), {"answer": answer}, follow=True)
        self.client.post(reverse("accounts:verify-pin"), {"pin": pin}, follow=True)

        # Voice Factor handling
        user = User.objects.get(email=email)
        if "voice_challenge_phrase" in self.client.session:
            voice_phrase = self.client.session["voice_challenge_phrase"]
            path = reverse("accounts:verify-voice")
            if not user.voice_enabled:
                path = reverse("accounts:verify-voice-setup")
            self.client.post(
                path,
                {"spoken_phrase": voice_phrase, "audio_file": self.voice_sample()},
                follow=True,
            )

        # Passkey Factor handling (Setup if required)
        self.client.post(reverse("accounts:verify-passkey-setup"), follow=True)

        response = self.client.get(reverse("accounts:choose-factor"), follow=True)
        if totp_code is not None:
            response = self.client.post(reverse("accounts:verify-totp"), {"otp": totp_code}, follow=True)
        return response

    def test_admin_reaches_admin_dashboard(self):
        admin = User.objects.create_user(
            email="admin@example.com",
            password="AdminPass123456!",
            role=User.Role.ADMIN,
            is_staff=True,
            phone_number="9999999999",
            security_question=User.SecurityQuestion.CITY,
        )
        admin.set_security_answer("davangere")
        admin.set_pin("1234")
        admin.ensure_totp_secret()
        admin.totp_enabled = True
        admin.save(update_fields=["security_answer_hash", "pin_hash", "totp_secret", "totp_enabled"])
        response = self.complete_mfa_login(
            admin.email,
            "AdminPass123456!",
            totp_code=pyotp.TOTP(admin.totp_secret).now(),
            answer="davangere",
            pin="1234",
        )
        self.assertRedirects(response, reverse("accounts:admin-dashboard"))

    def test_user_cannot_access_admin_dashboard(self):
        user = User.objects.create_user(
            email="user@example.com",
            password="UserPass123456!",
            phone_number="8888888888",
            security_question=User.SecurityQuestion.SCHOOL,
        )
        user.set_security_answer("gm")
        user.set_pin("4321")
        user.ensure_totp_secret()
        user.totp_enabled = True
        user.save(update_fields=["security_answer_hash", "pin_hash", "totp_secret", "totp_enabled"])
        self.complete_mfa_login(
            user.email,
            "UserPass123456!",
            totp_code=pyotp.TOTP(user.totp_secret).now(),
            answer="gm",
            pin="4321",
        )
        response = self.client.get(reverse("accounts:admin-dashboard"), follow=True)
        self.assertRedirects(response, reverse("accounts:user-dashboard"))

    def test_trusted_device_still_requires_full_mfa_on_next_login(self):
        user = User.objects.create_user(
            email="trusted@example.com",
            password="UserPass123456!",
            security_question=User.SecurityQuestion.SCHOOL,
        )
        user.set_security_answer("gm")
        user.set_pin("4321")
        user.ensure_totp_secret()
        user.totp_enabled = True
        user.save(update_fields=["security_answer_hash", "pin_hash", "totp_secret", "totp_enabled"])

        self.complete_mfa_login(
            user.email,
            "UserPass123456!",
            totp_code=pyotp.TOTP(user.totp_secret).now(),
            answer="gm",
            pin="4321",
        )
        self.assertEqual(TrustedDevice.objects.filter(user=user).count(), 1)
        trusted_cookie = self.client.cookies[settings.TRUSTED_DEVICE_COOKIE_NAME].value

        self.client.logout()
        self.client.cookies[settings.TRUSTED_DEVICE_COOKIE_NAME] = trusted_cookie
        response = self.client.post(reverse("accounts:login"), {"username": user.email, "password": "UserPass123456!"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-otp"))

        challenge = OTPChallenge.objects.filter(user=user, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        challenge.code_hash = OTPChallenge.hash_code("123456")
        challenge.save(update_fields=["code_hash"])
        response = self.client.post(reverse("accounts:verify-otp"), {"otp": "123456"}, follow=True)

        self.assertRedirects(response, reverse("accounts:verify-captcha"))
        response = self.client.post(reverse("accounts:verify-captcha"), {"captcha_checkbox": True}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-image"))
        image_challenge = self.client.session["image_challenge"]
        response = self.client.post(reverse("accounts:verify-image"), {"image_choices": image_challenge["correct_keys"]}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-text-captcha"))
        text_captcha = self.client.session["text_captcha"]
        response = self.client.post(reverse("accounts:verify-text-captcha"), {"captcha_input": text_captcha}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-question"))
        self.client.post(reverse("accounts:verify-question"), {"answer": "gm"}, follow=True)
        response = self.client.post(reverse("accounts:verify-pin"), {"pin": "4321"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-totp"))
        self.client.post(reverse("accounts:verify-totp"), {"otp": pyotp.TOTP(user.totp_secret).now()}, follow=True)
        self.assertTrue(LoginActivity.objects.filter(user=user, status=LoginActivity.Status.SUCCESS, is_trusted_device=True).exists())


class ProfileAndAdminLogTests(TestCase):
    def sign_in_verified(self, user):
        self.client.force_login(user)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()

    def test_verified_user_can_view_profile_details(self):
        user = User.objects.create_user(
            email="profile@example.com",
            password="UserPass123456!",
            first_name="Cloud",
            last_name="Member",
        )
        self.sign_in_verified(user)

        response = self.client.get(reverse("accounts:profile"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Cloud Member")
        self.assertContains(response, "profile@example.com")
        self.assertContains(response, "User")
        self.assertContains(response, "Member Since")
        self.assertNotContains(response, "Your latest logs")
        self.assertNotContains(response, "Recent activity")
        self.assertNotContains(response, "Trusted devices")

    def test_admin_can_view_all_logs(self):
        admin = User.objects.create_user(
            email="admin-logs@example.com",
            password="AdminPass123456!",
            role=User.Role.ADMIN,
            is_staff=True,
        )
        member = User.objects.create_user(email="member-log@example.com", password="UserPass123456!")
        LoginActivity.objects.create(
            user=member,
            email=member.email,
            status=LoginActivity.Status.SUCCESS,
            detail="All MFA factors completed successfully.",
        )
        self.sign_in_verified(admin)

        response = self.client.get(reverse("accounts:admin-logs"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "member-log@example.com")
        self.assertContains(response, "All MFA factors completed successfully.")

    def test_standard_user_cannot_view_admin_logs(self):
        user = User.objects.create_user(email="standard@example.com", password="UserPass123456!")
        self.sign_in_verified(user)

        response = self.client.get(reverse("accounts:admin-logs"), follow=True)

        self.assertRedirects(response, reverse("accounts:user-dashboard"))

    def test_private_nav_waits_for_completed_mfa(self):
        user = User.objects.create_user(email="pending@example.com", password="UserPass123456!")
        self.client.force_login(user)
        session = self.client.session
        session["mfa_verified"] = False
        session.save()

        response = self.client.get(reverse("accounts:home"))

        self.assertContains(response, "Login")
        self.assertContains(response, "Register")
        self.assertNotContains(response, 'href="/dashboard/"')
        self.assertNotContains(response, "Logout</button>")
