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
    from_email = settings.EMAIL_HOST_USER
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

from .models import User

class UserRegistration(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_description="This is for Customer Registration",
        operation_summary="Customer can Register using this API",
        tags=['Authentication'],
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
            date=timezone.now()
            user = User.objects.create(email=email, password=user_password,date_joined=date)
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
        tags=['Authentication'],
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
                return Response({"status": status.HTTP_200_OK, 'message': 'Login successfully', 'token': token}, status=status.HTTP_200_OK)
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
    @swagger_auto_schema(
        operation_description="Forgot password functionality. Sends a password reset link to the provided email address.",
        operation_summary="Forgot Password",
        tags=['Authentication'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
            },
        ),
        responses={
            200: 'Password reset email sent successfully',
            400: 'Bad request: Email is required',
            404: 'User not found',
        }
    )
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
        reset_link = f"http://127.0.0.1:8000/reset-password/{uid}/{token}/"
        
        from_email = settings.EMAIL_HOST_USER
        email_subject = 'Password Reset'
        email_body = f'reset_link: {reset_link}'
        send_mail(email_subject, email_body, from_email ,[user.email] )
        
        return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)


class ResetPassword(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        operation_description="Reset password functionality. Sets a new password for the user with the provided reset link.",
        operation_summary="Reset Password",
        tags=['Authentication'],
        manual_parameters=[
            openapi.Parameter('uidb64', openapi.IN_PATH, description="User ID encoded in base64", type=openapi.TYPE_STRING),
            openapi.Parameter('token', openapi.IN_PATH, description="Token for password reset", type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['new_password'],
            properties={
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New password for the user'),
            },
        ),
        responses={
            200: 'Password reset successfully',
            400: 'Bad request: Invalid reset link or new password is required',
        }
    )
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as e:
            user = None
            return Response({"response":f'{str(e)}',"status":status.HTTP_400_BAD_REQUEST})
        try:
            if user is not None and default_token_generator.check_token(user, token):
                new_password = request.data.get('new_password')
                
                if not new_password:
                    return Response({'message': 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
                
                user.set_password(new_password)
                user.save()
                
                return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Invalid reset link'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"response":f'{str(e)}',"status":status.HTTP_400_BAD_REQUEST})



class AddPersonalDetails(APIView):
    @swagger_auto_schema(
        operation_description="Add personal details for a user.",
        operation_summary="Add Personal Details",
        tags=['Personal Details'],
        request_body=PersonalDetailsSerializer,
        responses={
            201: 'Personal details added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            serializer = PersonalDetailsSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response":f'{str(e)}',"status":status.HTTP_500_INTERNAL_SERVER_ERROR},status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetPersonalDetails(APIView):
    @swagger_auto_schema(
        operation_description="Get all personal details of users.",
        operation_summary="Get Personal Details",
        tags=['Personal Details'],
        responses={
            200: 'Personal details retrieved successfully',
        }
    )
    def get(self, request):
        try:
            personal_details = PersonalDetails.objects.all()
            serializer = PersonalDetailsSerializer(personal_details, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response":f'{str(e)}',"status":status.HTTP_500_INTERNAL_SERVER_ERROR},status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdatePersonalDetails(APIView):
    @swagger_auto_schema(
        operation_description="Update personal details for a user.",
        operation_summary="Update Personal Details",
        tags=['Personal Details'],
        request_body=PersonalDetailsSerializer,
        responses={
            200: 'Personal details updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Personal details not found'
        }
    )
    def put(self, request, email):
        try:
            personal_details = PersonalDetails.objects.get(user__email=email)
        except PersonalDetails.DoesNotExist:
            return Response({'message': 'Personal details not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = PersonalDetailsSerializer(personal_details, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response":f'{str(e)}',"status":status.HTTP_500_INTERNAL_SERVER_ERROR},status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeletePersonalDetails(APIView):
    @swagger_auto_schema(
        operation_description="Delete personal details for a user.",
        operation_summary="Delete Personal Details",
        tags=['Personal Details'],
        responses={
            204: 'Personal details deleted successfully',
            404: 'Personal details not found'
        }
    )
    def delete(self, request, email):
        try:
            personal_details = PersonalDetails.objects.get(user__email=email)
        except PersonalDetails.DoesNotExist:
            return Response({'message': 'Personal details not found'}, status=status.HTTP_404_NOT_FOUND)
        personal_details.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
    

class AddEducation(APIView):
    pass



class GetEducation(APIView):
    pass


class AddExperience(APIView):
    pass


class GetExperience(APIView):
    pass


class AddSkill(APIView):
    pass


class GetSkill(APIView):
    pass


class AddSkill(APIView):
    pass


class AddCertificate(APIView):
    pass


class GetCertificate(APIView):
    pass


class AddAchievement(APIView):
    pass


class GetAchievement(APIView):
    pass


class GetAllDetails(APIView):
    pass


class ExportResume(APIView):
    pass