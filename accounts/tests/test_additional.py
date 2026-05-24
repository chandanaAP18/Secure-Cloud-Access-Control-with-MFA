from django.test import TestCase
from django.contrib.auth import get_user_model
from auditlog.models import LoginActivity
from accounts.services import get_client_ip
from django.test import RequestFactory

User = get_user_model()

class AuditLogTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(email="audit@example.com", password="Password123!")

    def test_login_activity_creation(self):
        request = self.factory.get("/")
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        request.META['HTTP_USER_AGENT'] = 'TestAgent'
        
        activity = LoginActivity.objects.create(
            user=self.user,
            email=self.user.email,
            ip_address=get_client_ip(request),
            user_agent=request.META['HTTP_USER_AGENT'],
            status=LoginActivity.Status.SUCCESS
        )
        
        self.assertEqual(LoginActivity.objects.count(), 1)
        self.assertEqual(activity.ip_address, '192.168.1.1')
        self.assertEqual(activity.status, LoginActivity.Status.SUCCESS)

from django.urls import reverse

class PasswordResetTests(TestCase):
    def test_password_reset_page_load(self):
        response = self.client.get(reverse('accounts:password-reset'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Reset Your Password")
