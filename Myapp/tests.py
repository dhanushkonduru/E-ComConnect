from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.utils import timezone
from django.contrib.auth.models import User
from Myapp.utils import generate_otp


class AuthTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.user_data = {
            'username': 'testuser',
            'password': 'testpassword',
            'country_code': '+1',
            'phone': '1234567890'
        }

    def test_user_registration_and_login(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print('Response:', response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username='testuser')
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now()
        user.save()

        login_data = {
            'phone': '1234567890',
            'country_code': '+1',
            'otp': otp
        }
        response = self.client.post(self.login_url, login_data, format='json')
        if response.status_code != status.HTTP_200_OK:
            print('Response:', response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)

    def test_login_with_invalid_otp(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print('Response:', response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        login_data = {
            'phone': '1234567890',
            'country_code': '+1',
            'otp': '000000'
        }
        response = self.client.post(self.login_url, login_data, format='json')
        if response.status_code != status.HTTP_400_BAD_REQUEST:
            print('Response:', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Invalid OTP or OTP expired')

    def test_login_with_expired_otp(self):
        response = self.client.post(self.register_url, self.user_data, format='json')
        if response.status_code != status.HTTP_201_CREATED:
            print('Response:', response.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username='testuser')
        otp = generate_otp()
        user.otp = otp
        user.otp_created_at = timezone.now() - timezone.timedelta(minutes=15)
        user.save()

        login_data = {
            'phone': '1234567890',
            'country_code': '+1',
            'otp': otp
        }
        response = self.client.post(self.login_url, login_data, format='json')
        if response.status_code != status.HTTP_400_BAD_REQUEST:
            print('Response:', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Invalid OTP or OTP expired')
