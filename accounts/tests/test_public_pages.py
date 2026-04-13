from django.test import TestCase
from django.urls import reverse


class PublicPageTests(TestCase):
    def test_public_pages_render(self):
        for name in ["accounts:home", "accounts:about", "accounts:how-it-works"]:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200)

    def test_login_page_offers_voice_email_input(self):
        response = self.client.get(reverse("accounts:login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-voice-target="id_username"')
        self.assertContains(response, 'data-voice-target="id_password"')
        self.assertContains(response, 'data-voice-assistant')
        self.assertContains(response, "You can type your email or use voice input to fill it automatically.")
        self.assertContains(response, "the flow can also continue with face unlock, fingerprint, or Windows Hello")

    def test_register_page_renders(self):
        response = self.client.get(reverse("accounts:register"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create a normal user account")
