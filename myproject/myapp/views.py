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
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add personal details for a user.",
        operation_summary="Add Personal Details",
        tags=['Personal Details'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=PersonalDetailsSerializer,
        responses={
            201: 'Personal details added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            user = request.user
            request.data['user'] = user.id
            serializer = PersonalDetailsSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetPersonalDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all personal details of the authenticated user.",
        operation_summary="Get Personal Details",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Personal Details'],
        responses={
            200: 'Personal details retrieved successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user
            personal_details = PersonalDetails.objects.filter(user=user)
            serializer = PersonalDetailsSerializer(personal_details, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdatePersonalDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update personal details for the authenticated user.",
        operation_summary="Update Personal Details",
        tags=['Personal Details'],
        request_body=PersonalDetailsSerializer,
        responses={
            200: 'Personal details updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Personal details not found'
        }
    )
    def put(self, request):
        try:
            user = request.user
            personal_details = PersonalDetails.objects.get(user=user)
        except PersonalDetails.DoesNotExist:
            return Response({'message': 'Personal details not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = PersonalDetailsSerializer(personal_details, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeletePersonalDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete personal details for the authenticated user.",
        operation_summary="Delete Personal Details",
        tags=['Personal Details'],
        responses={
            204: 'Personal details deleted successfully',
            404: 'Personal details not found'
        }
    )
    def delete(self, request):
        try:
            user = request.user
            personal_details = PersonalDetails.objects.get(user=user)
        except PersonalDetails.DoesNotExist:
            return Response({'message': 'Personal details not found'}, status=status.HTTP_404_NOT_FOUND)
        personal_details.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

class AddEducation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add education details for a user.",
        operation_summary="Add Education",
        tags=['Education'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=EducationSerializer,
        responses={
            201: 'Education details added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            user = request.user
            request.data['user'] = user.id
            serializer = EducationSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetEducation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all education details of the authenticated user.",
        operation_summary="Get Education",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Education'],
        responses={
            200: 'Education details retrieved successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user
            education = Education.objects.filter(user=user)
            serializer = EducationSerializer(education, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateEducation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update education details for the authenticated user.",
        operation_summary="Update Education",
        tags=['Education'],
        request_body=EducationSerializer,
        responses={
            200: 'Education details updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Education details not found'
        }
    )
    def put(self, request):
        try:
            user = request.user
            education = Education.objects.get(user=user)
        except Education.DoesNotExist:
            return Response({'message': 'Education details not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = EducationSerializer(education, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteEducation(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete education details for the authenticated user.",
        operation_summary="Delete Education",
        tags=['Education'],
        responses={
            204: 'Education details deleted successfully',
            404: 'Education details not found'
        }
    )
    def delete(self, request):
        try:
            user = request.user
            education = Education.objects.get(user=user)
        except Education.DoesNotExist:
            return Response({'message': 'Education details not found'}, status=status.HTTP_404_NOT_FOUND)
        education.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddExperience(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add work experience details for a user.",
        operation_summary="Add Experience",
        tags=['Experience'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=WorkExperienceSerializer,
        responses={
            201: 'Work experience details added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            user = request.user
            request.data['user'] = user.id
            serializer = WorkExperienceSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetExperience(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all work experience details of the authenticated user.",
        operation_summary="Get Experience",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Experience'],
        responses={
            200: 'Work experience details retrieved successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user
            experience = WorkExperience.objects.filter(user=user)
            serializer = WorkExperienceSerializer(experience, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateExperience(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update work experience details for the authenticated user.",
        operation_summary="Update Experience",
        tags=['Experience'],
        request_body=WorkExperienceSerializer,
        responses={
            200: 'Work experience details updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Work experience details not found'
        }
    )
    def put(self, request):
        try:
            user = request.user
            experience = WorkExperience.objects.get(user=user)
        except WorkExperience.DoesNotExist:
            return Response({'message': 'Work experience details not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = WorkExperienceSerializer(experience, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteExperience(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete work experience details for the authenticated user.",
        operation_summary="Delete Experience",
        tags=['Experience'],
        responses={
            204: 'Work experience details deleted successfully',
            404: 'Work experience details not found'
        }
    )
    def delete(self, request):
        try:
            user = request.user
            experience = WorkExperience.objects.get(user=user)
        except WorkExperience.DoesNotExist:
            return Response({'message': 'Work experience details not found'}, status=status.HTTP_404_NOT_FOUND)
        experience.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddSkill(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add a skill for the authenticated user.",
        operation_summary="Add Skill",
        tags=['Skill'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=SkillSerializer,
        responses={
            201: 'Skill added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            user = request.user
            request.data['user'] = user.id
            serializer = SkillSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetSkill(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all skills of the authenticated user.",
        operation_summary="Get Skill",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Skill'],
        responses={
            200: 'Skills retrieved successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user
            skills = Skill.objects.filter(user=user)
            serializer = SkillSerializer(skills, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateSkill(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update a skill for the authenticated user.",
        operation_summary="Update Skill",
        tags=['Skill'],
        request_body=SkillSerializer,
        responses={
            200: 'Skill updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Skill not found'
        }
    )
    def put(self, request):
        try:
            user = request.user
            skill = Skill.objects.get(user=user)
        except Skill.DoesNotExist:
            return Response({'message': 'Skill not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = SkillSerializer(skill, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteSkill(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a skill for the authenticated user.",
        operation_summary="Delete Skill",
        tags=['Skill'],
        responses={
            204: 'Skill deleted successfully',
            404: 'Skill not found'
        }
    )
    def delete(self, request):
        try:
            user = request.user
            skill = Skill.objects.get(user=user)
        except Skill.DoesNotExist:
            return Response({'message': 'Skill not found'}, status=status.HTTP_404_NOT_FOUND)
        skill.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddCertificate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add a certificate for the authenticated user.",
        operation_summary="Add Certificate",
        tags=['Certificate'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=CertificateSerializer,
        responses={
            201: 'Certificate added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            user = request.user
            request.data['user'] = user.id
            serializer = CertificateSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetCertificate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all certificates of the authenticated user.",
        operation_summary="Get Certificate",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Certificate'],
        responses={
            200: 'Certificates retrieved successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user
            certificates = Certificate.objects.filter(user=user)
            serializer = CertificateSerializer(certificates, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateCertificate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update a certificate for the authenticated user.",
        operation_summary="Update Certificate",
        tags=['Certificate'],
        request_body=CertificateSerializer,
        responses={
            200: 'Certificate updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Certificate not found'
        }
    )
    def put(self, request):
        try:
            user = request.user
            certificate = Certificate.objects.get(user=user)
        except Certificate.DoesNotExist:
            return Response({'message': 'Certificate not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = CertificateSerializer(certificate, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteCertificate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a certificate for the authenticated user.",
        operation_summary="Delete Certificate",
        tags=['Certificate'],
        responses={
            204: 'Certificate deleted successfully',
            404: 'Certificate not found'
        }
    )
    def delete(self, request):
        try:
            user = request.user
            certificate = Certificate.objects.get(user=user)
        except Certificate.DoesNotExist:
            return Response({'message': 'Certificate not found'}, status=status.HTTP_404_NOT_FOUND)
        certificate.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddAchievement(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add an achievement for the authenticated user.",
        operation_summary="Add Achievement",
        tags=['Achievement'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=AchievementSerializer,
        responses={
            201: 'Achievement added successfully',
            400: 'Bad request: Invalid data provided'
        }
    )
    def post(self, request):
        try:
            user = request.user
            request.data['user'] = user.id
            serializer = AchievementSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetAchievement(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all achievements of the authenticated user.",
        operation_summary="Get Achievement",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Achievement'],
        responses={
            200: 'Achievements retrieved successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user
            achievements = Achievement.objects.filter(user=user)
            serializer = AchievementSerializer(achievements, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateAchievements(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update an achievement for the authenticated user.",
        operation_summary="Update Achievement",
        tags=['Achievement'],
        request_body=AchievementSerializer,
        responses={
            200: 'Achievement updated successfully',
            400: 'Bad request: Invalid data provided',
            404: 'Achievement not found'
        }
    )
    def put(self, request):
        try:
            user = request.user
            achievement = Achievement.objects.get(user=user)
        except Achievement.DoesNotExist:
            return Response({'message': 'Achievement not found'}, status=status.HTTP_404_NOT_FOUND)
        try:
            serializer = AchievementSerializer(achievement, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteAchievements(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete an achievement for the authenticated user.",
        operation_summary="Delete Achievement",
        tags=['Achievement'],
        responses={
            204: 'Achievement deleted successfully',
            404: 'Achievement not found'
        }
    )
    def delete(self, request):
        try:
            user = request.user
            achievement = Achievement.objects.get(user=user)
        except Achievement.DoesNotExist:
            return Response({'message': 'Achievement not found'}, status=status.HTTP_404_NOT_FOUND)
        achievement.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# class GetAllDetails(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAuthenticated]

#     @swagger_auto_schema(
#         operation_description="Get all details of the authenticated user.",
#         operation_summary="Get All Details",
#         manual_parameters=[
#             openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
#         ],
#         tags=['User Details'],
#         responses={
#             200: 'User details retrieved successfully',
#         }
#     )
#     def get(self, request):
#         try:
#             user = request.user
#             user_details = {
#                 'personal_details': None,
#                 'educations': None,
#                 'experiences': None,
#                 'skills': None,
#                 'projects': None,
#                 'certificates': None,
#                 'achievements': None
#             }
#             # Personal Details
#             personal_details = PersonalDetails.objects.filter(user=user).first()
#             if personal_details:
#                 user_details['personal_details'] = PersonalDetailsSerializer(personal_details).data
            
#             # Education
#             educations = Education.objects.filter(user=user).exclude(degree=None, specialization=None, institution=None).all()
#             if educations:
#                 user_details['educations'] = EducationSerializer(educations, many=True).data
            
#             # Work Experience
#             experiences = WorkExperience.objects.filter(user=user).exclude(company=None, position=None).all()
#             if experiences:
#                 user_details['experiences'] = WorkExperienceSerializer(experiences, many=True).data
            
#             # Skills
#             skills = Skill.objects.filter(user=user).exclude(skill_name=None).all()
#             if skills:
#                 user_details['skills'] = SkillSerializer(skills, many=True).data
            
#             # Projects
#             projects = Project.objects.filter(user=user).exclude(project_name=None).all()
#             if projects:
#                 user_details['projects'] = ProjectSerializer(projects, many=True).data
            
#             # Certificates
#             certificates = Certificate.objects.filter(user=user).exclude(certification_name=None).all()
#             if certificates:
#                 user_details['certificates'] = CertificateSerializer(certificates, many=True).data
            
#             # Achievements
#             achievements = Achievement.objects.filter(user=user).exclude(achievment_description=None).all()
#             if achievements:
#                 user_details['achievements'] = AchievementSerializer(achievements, many=True).data
            
#             return Response(user_details, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)




from rest_framework.response import Response
from rest_framework.views import APIView
from .models import PersonalDetails, Education, WorkExperience, Skill, Project, Certificate, Achievement
from .serializers import PersonalDetailsSerializer, EducationSerializer, WorkExperienceSerializer, SkillSerializer, ProjectSerializer, CertificateSerializer, AchievementSerializer


class GetAllDetails(APIView):
    def get(self, request):
        try:
            user = request.user

            # Retrieve personal details
            personal_details = PersonalDetails.objects.filter(user=user)
            personal_details_data = PersonalDetailsSerializer(personal_details, many=True).data

            # Retrieve non-null educations
            educations = Education.objects.filter(user=user).exclude(degree__isnull=True)
            educations_data = EducationSerializer(educations, many=True).data

            # Retrieve non-null experiences
            experiences = WorkExperience.objects.filter(user=user).exclude(company__isnull=True)
            experiences_data = WorkExperienceSerializer(experiences, many=True).data

            # Retrieve non-null skills
            skills = Skill.objects.filter(user=user).exclude(skill_name__isnull=True)
            skills_data = SkillSerializer(skills, many=True).data

            # Retrieve non-null projects
            projects = Project.objects.filter(user=user).exclude(project_name__isnull=True)
            projects_data = ProjectSerializer(projects, many=True).data

            # Retrieve non-null certificates
            certificates = Certificate.objects.filter(user=user).exclude(certification_name__isnull=True)
            certificates_data = CertificateSerializer(certificates, many=True).data

            # Retrieve non-null achievements
            achievements = Achievement.objects.filter(user=user).exclude(achievment_description__isnull=True)
            achievements_data = AchievementSerializer(achievements, many=True).data

            response_data = {
                "personal_details": personal_details_data,
                "educations": educations_data,
                "experiences": experiences_data,
                "skills": skills_data,
                "projects": projects_data,
                "certificates": certificates_data,
                "achievements": achievements_data
            }

            return Response(response_data)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class AnalyseData(APIView):
    @swagger_auto_schema(
        operation_description="Provide analytics data on user activity.",
        operation_summary="Analyse Data",

        tags=['Analytics'],
        responses={
            200: 'Analytics data retrieved successfully',
        }
    )
    def get(self, request):
        try:
            
            personal_details = PersonalDetails.objects.all()
            educations = Education.objects.all()
            experiences = WorkExperience.objects.all()
            skills = Skill.objects.all()
            projects = Project.objects.all()
            certificates = Certificate.objects.all()
            achievements = Achievement.objects.all()

            # Analyse data
            num_resumes_created = personal_details.count()
            most_common_skills = self.get_most_common_skills(skills)
            
            analytics_data = {
                'num_resumes_created': num_resumes_created,
                'most_common_skills': most_common_skills,
            }
            
            return Response(analytics_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_most_common_skills(self, skills):
        skill_counts = {}
        for skill in skills:
            skill_name = skill.skill_name
            if skill_name in skill_counts:
                skill_counts[skill_name] += 1
            else:
                skill_counts[skill_name] = 1
        
        most_common_skills = sorted(skill_counts.items(), key=lambda x: x[1], reverse=True)
        return most_common_skills[:5]  # Return top 5 most common skills

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas




# class ExportResume(APIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [IsAuthenticated]

#     @swagger_auto_schema(
#         operation_description="Export resume details to PDF.",
#         operation_summary="Export Resume",
#         manual_parameters=[
#             openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
#         ],
#         tags=['Resume'],
#         responses={
#             200: 'Resume details exported successfully',
#         }
#     )
#     def get(self, request):
#         try:
#             user = request.user

#             # Fetch user's resume details
#             personal_details = PersonalDetails.objects.get(user=user)
#             educations = Education.objects.filter(user=user).all()
#             experiences = WorkExperience.objects.filter(user=user).all()
#             skills = Skill.objects.filter(user=user).all()
#             projects = Project.objects.filter(user=user).all()
#             certificates = Certificate.objects.filter(user=user).all()
#             achievements = Achievement.objects.filter(user=user).all()

#             # Create a PDF document
#             response = HttpResponse(content_type='application/pdf')
#             response['Content-Disposition'] = 'attachment; filename="resume.pdf"'
#             p = canvas.Canvas(response, pagesize=letter)

#             # Add resume details to PDF
#             p.drawString(100, 800, 'Personal Details:')
#             p.drawString(100, 780, f'Mobile Number: {personal_details.mobile_number}')
#             p.drawString(100, 760, f'Address: {personal_details.address}')
#             # Add more personal details as needed

#             # Add education details to PDF
#             p.drawString(100, 700, 'Education:')
#             y_position = 680
#             for education in educations:
#                 p.drawString(100, y_position, f'Degree: {education.degree}')
#                 p.drawString(100, y_position - 20, f'Institution: {education.institution}')
#                 # Add more education details as needed
#                 y_position -= 40

#             # Add work experience details to PDF
#             # Add skills, projects, certificates, achievements similarly

#             p.showPage()
#             p.save()

#             return response
#         except Exception as e:
#             return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)



from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa
from io import BytesIO
from .models import PersonalDetails, Education, WorkExperience, Skill, Project, Certificate, Achievement


class ExportResume(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Export resume details to PDF.",
        operation_summary="Export Resume",
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['Resume'],
        responses={
            200: 'Resume details exported successfully',
        }
    )
    def get(self, request):
        try:
            user = request.user

            # Fetch user's resume details
            personal_details = PersonalDetails.objects.get(user=user)
            educations = Education.objects.filter(user=user).exclude(degree__isnull=True)
            experiences = WorkExperience.objects.filter(user=user).exclude(company__isnull=True)
            skills = Skill.objects.filter(user=user).exclude(skill_name__isnull=True)
            projects = Project.objects.filter(user=user).exclude(project_name__isnull=True)
            certificates = Certificate.objects.filter(user=user).exclude(certification_name__isnull=True)
            achievements = Achievement.objects.filter(user=user).exclude(achievment_description__isnull=True)

            # Create resume HTML content
            template = get_template('resume_template.html')
            context = {
                'personal_details': personal_details,
                'educations': educations,
                'experiences': experiences,
                'skills': skills,
                'projects': projects,
                'certificates': certificates,
                'achievements': achievements,
            }
            html = template.render(context)

            # Create PDF from HTML content
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="resume.pdf"'
            pisa_status = pisa.CreatePDF(html, dest=response)

            if pisa_status.err:
                return HttpResponse('PDF generation error', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return response
        except Exception as e:
            return Response({"Response": f'{str(e)}', "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status.HTTP_500_INTERNAL_SERVER_ERROR)



def render_page(request):
    return render (request,'resume_template.html')