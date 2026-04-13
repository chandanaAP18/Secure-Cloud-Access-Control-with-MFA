from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import OTPChallenge
from auditlog.models import LoginActivity
import pyotp

User = get_user_model()


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
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
        self.user.save(update_fields=["security_answer_hash", "pin_hash"])

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
        self.assertRedirects(response, reverse("accounts:verify-otp"))

        phone_otp = OTPChallenge.objects.filter(user=self.user, factor=OTPChallenge.Factor.PHONE).latest("created_at")
        phone_otp.code_hash = OTPChallenge.hash_code("654321")
        phone_otp.save(update_fields=["code_hash"])

        response = self.client.post(reverse("accounts:verify-otp"), {"otp": "654321"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-captcha"))

        captcha_code = self.client.session["captcha_challenge"]
        response = self.client.post(reverse("accounts:verify-captcha"), {"captcha": captcha_code}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-image"))

        image_answer = self.client.session["image_challenge"]["answer"]
        response = self.client.post(reverse("accounts:verify-image"), {"image_choice": image_answer}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-question"))

        response = self.client.post(reverse("accounts:verify-question"), {"answer": "bruno"}, follow=True)
        self.assertRedirects(response, reverse("accounts:verify-pin"))

        response = self.client.post(reverse("accounts:verify-pin"), {"pin": "1234"}, follow=True)
        self.assertRedirects(response, reverse("accounts:user-dashboard"))

        self.assertEqual(LoginActivity.objects.filter(status=LoginActivity.Status.OTP_SENT).count(), 2)
        self.assertGreaterEqual(LoginActivity.objects.filter(status=LoginActivity.Status.SUCCESS).count(), 6)
        self.assertIn("text/html", [alt[1] for alt in mail.outbox[0].alternatives])

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
