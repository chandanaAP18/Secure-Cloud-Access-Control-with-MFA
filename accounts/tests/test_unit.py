from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase

from accounts.models import OTPChallenge, PasskeyCredential
from accounts.services import get_client_ip, scan_document_file
from accounts.voice_biometrics import phrase_matches_expected
from accounts.views import build_mfa_queue

User = get_user_model()


class OTPChallengeModelTests(TestCase):
    def test_generated_otp_is_hashed_and_verifiable(self):
        user = User.objects.create_user(email="user@example.com", password="StrongPassword123!")
        challenge, plain_code = OTPChallenge.create_for_user(user, factor=OTPChallenge.Factor.EMAIL, destination=user.email)

        self.assertNotEqual(challenge.code_hash, plain_code)
        self.assertTrue(challenge.verify(plain_code))

    def test_ensure_totp_secret_persists_for_saved_users(self):
        user = User.objects.create_user(email="totp@example.com", password="StrongPassword123!")

        secret = user.ensure_totp_secret()
        user.refresh_from_db()

        self.assertEqual(user.totp_secret, secret)


class MFAQueueTests(TestCase):
    def test_login_queue_includes_text_captcha_totp_and_passkey_in_sequence(self):
        user = User.objects.create_user(
            email="queue@example.com",
            password="StrongPassword123!",
            security_question=User.SecurityQuestion.CITY,
        )
        user.set_security_answer("paris")
        user.set_pin("1234")
        user.ensure_totp_secret()
        user.totp_enabled = True
        user.save(update_fields=["security_answer_hash", "pin_hash", "totp_secret", "totp_enabled"])
        PasskeyCredential.objects.create(
            user=user,
            name="Primary Passkey",
            credential_id="credential-1",
            public_key=b"demo-key",
        )

        queue = build_mfa_queue(user, is_signup=False)

        self.assertEqual(
            queue,
            ["EMAIL", "CAPTCHA", "IMAGE", "TEXT_CAPTCHA", "QUESTION", "PIN", "VOICE_SETUP", "TOTP", "PASSKEY"],
        )

    def test_signup_queue_ends_with_totp_setup_when_passkey_not_registered(self):
        user = User.objects.create_user(
            email="signup-queue@example.com",
            password="StrongPassword123!",
            security_question=User.SecurityQuestion.PET,
        )
        user.set_security_answer("nova")
        user.set_pin("5678")
        user.save(update_fields=["security_answer_hash", "pin_hash"])

        queue = build_mfa_queue(user, is_signup=True)

        self.assertEqual(
            queue,
            ["EMAIL", "CAPTCHA", "IMAGE", "TEXT_CAPTCHA", "QUESTION", "PIN", "VOICE_SETUP", "TOTP_SETUP", "PASSKEY_SETUP"],
        )

    def test_login_queue_uses_setup_steps_for_missing_factors(self):
        user = User.objects.create_user(
            email="legacy@example.com",
            password="StrongPassword123!",
        )

        queue = build_mfa_queue(user, is_signup=False)

        self.assertEqual(
            queue,
            ["EMAIL", "CAPTCHA", "IMAGE", "TEXT_CAPTCHA", "QUESTION_SETUP", "PIN_SETUP", "VOICE_SETUP", "TOTP_SETUP", "PASSKEY_SETUP"],
        )


class RequestUtilitiesTests(SimpleTestCase):
    def test_x_forwarded_for_takes_priority(self):
        request = self.client.request().wsgi_request
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.1, 127.0.0.1"
        self.assertEqual(get_client_ip(request), "10.0.0.1")


class DocumentScanTests(SimpleTestCase):
    def test_scan_document_file_accepts_safe_pdf(self):
        upload = SimpleUploadedFile("report.pdf", b"%PDF-1.4 sample content")
        is_clean, message = scan_document_file(upload)

        self.assertTrue(is_clean)
        self.assertIn("passed the security scan", message)

    def test_scan_document_file_rejects_unsupported_extension(self):
        upload = SimpleUploadedFile("malware.exe", b"dummy content")
        is_clean, message = scan_document_file(upload)

        self.assertFalse(is_clean)
        self.assertIn("Unsupported document type", message)

    def test_scan_document_file_rejects_suspicious_content(self):
        upload = SimpleUploadedFile("notes.txt", b"Normal text <?php this is bad")
        is_clean, message = scan_document_file(upload)

        self.assertFalse(is_clean)
        self.assertIn("suspicious content", message)


class VoicePhraseMatchingTests(SimpleTestCase):
    def test_accepts_small_transcript_variation(self):
        self.assertTrue(
            phrase_matches_expected(
                "identity private portal netword",
                "identity private portal network",
            )
        )

    def test_rejects_substantially_different_phrase(self):
        self.assertFalse(
            phrase_matches_expected(
                "identity private token system",
                "identity private portal network",
            )
        )
