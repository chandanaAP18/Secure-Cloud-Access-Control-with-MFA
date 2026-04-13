from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from accounts.models import OTPChallenge
from accounts.services import get_client_ip

User = get_user_model()


class OTPChallengeModelTests(TestCase):
    def test_generated_otp_is_hashed_and_verifiable(self):
        user = User.objects.create_user(email="user@example.com", password="StrongPassword123!")
        challenge, plain_code = OTPChallenge.create_for_user(user, factor=OTPChallenge.Factor.EMAIL, destination=user.email)

        self.assertNotEqual(challenge.code_hash, plain_code)
        self.assertTrue(challenge.verify(plain_code))


class RequestUtilitiesTests(SimpleTestCase):
    def test_x_forwarded_for_takes_priority(self):
        request = self.client.request().wsgi_request
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.1, 127.0.0.1"
        self.assertEqual(get_client_ip(request), "10.0.0.1")
