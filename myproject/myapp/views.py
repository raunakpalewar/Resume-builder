from django.shortcuts import render, redirect
from django.http import HttpResponse
import requests
from django.http import HttpResponseRedirect
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAuthenticatedOrReadOnly, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import *
from .models import *
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import login, logout
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.conf import settings
from django.core.mail import send_mail
from datetime import timedelta
from django.db.models import Q
import re
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import EmailMessage

def send_updated_resume_email(email):
    subject = "Your Updated Resume"
    message = "Here is your updated resume"
    from_email = settings.Email_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)


def get_token_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


def password_validate(password):
    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(){}[\]:;,<>\'\"~])[A-Za-z\d!@#$%^&*(){}[\]:;,<>\'\"~]{8,16}$', password):
        raise ValueError("Password must be 8 to 16 characters long with one uppercase, one lowercase, a number, and a special character.")


def email_validate(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email or not re.match(email_regex, email):
        raise ValueError("Invalid email format")


class UserRegistration(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="This is for Customer Registration",
        operation_summary="Customer can Register using this API",
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['email', 'password']
        ),
    )
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            if not email or not password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Email or Password not provided"}, status=status.HTTP_400_BAD_REQUEST)

            email_validate(email)
            password_validate(password)

            user_password = make_password(password)
            user = User.objects.create(email=email, password=user_password)
            user.save()

            return Response({'message': "User Registered Successfully"}, status=status.HTTP_201_CREATED)

        except ValueError as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Login(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Login here",
        operation_summary='Login to your account',
        tags=['OAuth'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self, request):
        try:
            data = request.data
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid Input"}, status=status.HTTP_400_BAD_REQUEST)

            email_validate(email)
            password_validate(password)

            user = User.objects.get(email=email)

            if check_password(password, user.password):
                token = get_token_for_user(user)
                return Response({"status": status.HTTP_200_OK, 'message': 'Login successfully', 'token': token, "Your user id": user.id, 'You are': user.role}, status=status.HTTP_200_OK)
            else:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND, 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        except ValueError as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogout(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logout(request)
        return Response({"status": status.HTTP_200_OK, 'message': 'Logout successfully done'}, status=status.HTTP_200_OK)




class ForgotPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response({'message': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        
        # Construct reset password link
        reset_link = f"http://example.com/reset-password/{uid}/{token}/"
        
        # Send email with reset password link
        email_subject = 'Password Reset'
        email_body = f'reset_link: {reset_link}'
        email = EmailMessage(email_subject, email_body, to=[user.email])
        email.send()
        
        return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)


class ResetPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            
            if not new_password:
                return Response({'message': 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            user.set_password(new_password)
            user.save()
            
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid reset link'}, status=status.HTTP_400_BAD_REQUEST)