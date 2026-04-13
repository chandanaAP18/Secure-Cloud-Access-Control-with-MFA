from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import OTPChallenge
import pyotp

User = get_user_model()


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class RoleBasedSystemTests(TestCase):
    def complete_mfa_login(self, email, password, email_otp="654321", phone_otp="112233", totp_code=None, answer="gm", pin="4321"):
        self.client.post(reverse("accounts:login"), {"username": email, "password": password})
        challenge = OTPChallenge.objects.filter(user__email=email, factor=OTPChallenge.Factor.EMAIL).latest("created_at")
        challenge.code_hash = OTPChallenge.hash_code(email_otp)
        challenge.save(update_fields=["code_hash"])
        self.client.post(reverse("accounts:verify-otp"), {"otp": email_otp}, follow=True)

        phone = OTPChallenge.objects.filter(user__email=email, factor=OTPChallenge.Factor.PHONE).latest("created_at")
        phone.code_hash = OTPChallenge.hash_code(phone_otp)
        phone.save(update_fields=["code_hash"])
        self.client.post(reverse("accounts:verify-otp"), {"otp": phone_otp}, follow=True)

        captcha_code = self.client.session["captcha_challenge"]
        self.client.post(reverse("accounts:verify-captcha"), {"captcha": captcha_code}, follow=True)

        image_answer = self.client.session["image_challenge"]["answer"]
        self.client.post(reverse("accounts:verify-image"), {"image_choice": image_answer}, follow=True)

        if totp_code is not None:
            self.client.post(reverse("accounts:verify-totp"), {"otp": totp_code}, follow=True)

        self.client.post(reverse("accounts:verify-question"), {"answer": answer}, follow=True)
        return self.client.post(reverse("accounts:verify-pin"), {"pin": pin}, follow=True)

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
