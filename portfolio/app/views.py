from django.forms import ValidationError
from django.http import HttpResponseRedirect
import datetime
from django.utils.dateparse import parse_date
from datetime import timedelta
from django.utils import timezone
import random
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import login, logout
import re
from django.db.models import Q
from django.shortcuts import render
import random
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.response import Response
from rest_framework import status
from app.pagination import CustomPageNumberPagination
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from drf_yasg.views import get_schema_view
from app.serializers import (Category_management_model_serializer1,
                            Blog_Management_model_serializer1,
                            ServiceManagementModel_serializer2,
                            Brand_management_model_serializer2,
                            Portfolio_Management_model_serializer2,
                            Category_management_model_serializer,
                            ServiceManagementModel_serializer,
                            Portfolio_Management_model_serializer,
                            Blog_Management_model_serializer,
                            Brand_management_model_serializer,
                            MyuserSerializer,
                            FAQSerializer,
                            Static_ContentSerializer
                        )
from app.models import (ServiceManagementModel,
                        Portfolio_Management_model,
                        Category_management_model,
                        Blog_Management_model,
                        Brand_management_model,
                        static_content,FAQ,Myuser,
                        OldPassword_Model
                        )



 

API_BASE_URL = 'http://172.16.12.253:9090/'


def Send_email(email,subject,otp):
    send_mail(
        subject,
        str(otp),
        "pratap.patil@indicchain.com",
        [email],
        fail_silently=False
    )

class RegisterUser(APIView):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    password_regex = '^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)[A-Za-z\\d!@#$%^&*(){}[\\]:;,<>\'\"~]{8,16}$'
    @swagger_auto_schema(
        operation_description="The RegisterUser API is a crucial component of PortfolioHub's authentication system, allowing users to sign up securely. Users provide their name, email, password, and role, with the API enforcing email format and password strength criteria. Upon successful registration, a one-time password (OTP) is sent for email verification. The API ensures data integrity by securely storing user information in the database with hashed passwords. Exception handling is implemented to manage errors, providing clear responses to guide users. Overall, the RegisterUser API ensures a smooth and secure user onboarding process for PortfolioHub.",
        operation_summary="API used for user registration",
        tags=['AUTHFLOW'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[""],
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING, default='pratap1909@mailinator.com'),
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='pratap1909@mailinator.com'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, default="Pratap@123"),
                'role': openapi.Schema(type=openapi.TYPE_STRING, default='admin'),
            }
        ),
    )
    def post(self, request):
        data = request.data
        name = data['name']
        email = data['email']
        password = data['password']
        role = data['role']
        otp = random.randint(1111, 9999)
        if not re.match(self.email_regex, email):
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
        if not re.match(self.password_regex, password):
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password should contain 1 uppercase, 1 lowercase, any special symbol"}, status=status.HTTP_400_BAD_REQUEST)
        if Myuser.objects.filter(email=email).exists():
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Respponse': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            hashed_password = make_password(password)
            user = Myuser.objects.create(name=name, email=email, password=hashed_password, otp=otp, role=role, otp_created_at=timezone.now())
            user.save()
            newpassword=OldPassword_Model.objects.create(user=user,oldpassword=hashed_password)
            newpassword.save()
            subject="OTP for email verification"
            Send_email(email,subject,otp)
            return Response({'status': status.HTTP_200_OK, 'Response': 'User registered successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):
    @swagger_auto_schema(
        operation_description="The VerifyEmail API is a crucial step in PortfolioHubs authentication flow, enabling users to confirm their email addresses.Users submit their email and the received one-time password (OTP) for validation. The API checks the OTPs validity within a time limit of three minutes and updates the users status to verified upon successful verification In case of any issues, such as an invalid OTP or a timeout, the API provides clear responses. Overall, the API ensures a secure and efficient email verification process for users registering on the platform",
        operation_summary="API used for Verifing OTP for email verification.",
        tags=['AUTHFLOW'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default="pratap1909@mailinator.com"),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, default="1234")
            },
        ),
    )
    def post(self, request):
        data = request.data
        email=data['email']
        otp = int(data['otp'])
        try:
            user = Myuser.objects.get(email=email)
            time_difference = timezone.now() - user.otp_created_at
            if time_difference <= timedelta(minutes=3):
                if otp == user.otp:
                    user.is_valid = True
                    user.save()
                    return Response({'status':status.HTTP_200_OK,"message": "OTP verified successfully"},status.HTTP_200_OK)
                return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Invalid OTP"},status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "time out for OTP"},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": str(e)},status.HTTP_400_BAD_REQUEST)


from rest_framework_simplejwt.tokens import RefreshToken
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class Login(APIView):
    @swagger_auto_schema(
        operation_description="Fill in user login information",
        operation_summary="User login validating email and password",
        tags=['AUTHFLOW'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email','password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING,default='pratap1909@mailinator.com'),
                'password': openapi.Schema(type=openapi.TYPE_STRING,default='Pratap@123')
            }
        )
    )
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not email or not re.match(email_regex, email):
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = Myuser.objects.get(email=email)
            if user.is_valid==False:
                return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Email not verified. Please verify your email first."},status.HTTP_400_BAD_REQUEST)
            if user.is_block==True:
                return Response({'status':status.HTTP_403_FORBIDDEN,"message": "User is blocked by admin."},status.HTTP_403_FORBIDDEN)
            if check_password(password, user.password):
                login(request,user)
                user.is_active=True
                user.save()
                refresh = RefreshToken.for_user(user)
                return Response({"status": status.HTTP_200_OK,
                "message": "Login successful",
                "access_token": ('Bearer '+str(refresh.access_token)),
                "refresh_token": str(refresh)
                },status.HTTP_200_OK)
            else:
                return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        except Myuser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


# forget password:otp send
class ForgotPasswordView(APIView):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    @swagger_auto_schema(
        operation_description="API used for forget password",
        operation_summary="API used for forget password",
        tags=['AUTHFLOW'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='pratap1909@mailinator.com'),
            }
        ),
    )
    def post(self, request):
        data = request.data
        email=data['email']
        user=Myuser.objects.get(email=email)
        if not email:
            return Response({'message': 'Email id is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if not re.match(self.email_regex, email):
            return Response({'message': 'Please enter a valid email address.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = Myuser.objects.get(email=email)
        except Myuser.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        if user.is_block==True:
                return Response({'status':status.HTTP_403_FORBIDDEN,"message": "User is blocked by admin."},status.HTTP_403_FORBIDDEN)
        if user.is_valid==False:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Email not verified. Please verify your email first."},status.HTTP_400_BAD_REQUEST)
        otp=random.randint(1111,9999)
        user.otp=otp
        user.otp_created_at=timezone.now()
        user.otp_created_at
        user.save()
        subject="OTP for forget password "
        Send_email(email,subject,otp)
        return Response({'status':status.HTTP_200_OK,'message': 'OTP sent successfully for password reset.'}, status=status.HTTP_200_OK)


# reset password
class ChangePasswordView(APIView):
    @swagger_auto_schema(
        operation_description="API used for reset password if user forget password",
        operation_summary="API used for reset password if user forget password",
        tags=['AUTHFLOW'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['new_password', 'confirm_password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='pratap1909@mailinator.com'),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, default='Pratap@1234'),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, default='Pratap@1234'),
            }
        ),
    )
    def post(self, request):
        email = request.data['email']
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        try:
            user = Myuser.objects.get(email=email)
        except Myuser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        if user.is_block==True:
                return Response({'status':status.HTTP_403_FORBIDDEN,"message": "User is blocked by admin."},status.HTTP_403_FORBIDDEN)
        if user.is_valid==False:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Email not verified. Please verify your email first."},status.HTTP_400_BAD_REQUEST)
        password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
        if not re.match(password_regex, new_password):
            return Response({"message": "Invalid password format"}, status=status.HTTP_403_FORBIDDEN)
        old_passwords = OldPassword_Model.objects.filter(user=user).order_by('-id')[:3]
        for password_instance in old_passwords:
            if check_password(new_password, password_instance.oldpassword):
                return Response({'status': status.HTTP_400_BAD_REQUEST,
                                 'message': 'New password should not match with last 3 passwords'},
                                status=status.HTTP_400_BAD_REQUEST)
        if new_password != confirm_password:
            return Response({"message": "New password and Confirm password must be the same."}, status=status.HTTP_400_BAD_REQUEST)
        hash_password=make_password(new_password)
        user.password=hash_password
        user.save()
        # Save the new password to OldPassword_Model
        old_password_instance = OldPassword_Model.objects.create(user=user, oldpassword=hash_password)
        old_password_instance.save()
        return Response({'status': status.HTTP_200_OK, 'message': 'Password reset successfully'}, status=status.HTTP_200_OK)


# reset password
class ResetPasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
    operation_description="Resetting password in change password functionality",
    operation_summary="Resetting password",
    manual_parameters=[
        openapi.Parameter(
            'Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,description="JWT Token",
        ),
    ],
    tags=['AUTHFLOW'],
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email', 'current_password', 'new_password', 'confirm_password'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, default='pratap1909@mailinator.com'),
            'current_password': openapi.Schema(type=openapi.TYPE_STRING, default='Pratap@1234'),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING, default='Pratap@12345'),
            'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, default='Pratap@12345'),
        }
        ),
    )
    def post(self, request):
        email = request.data.get('email')
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        if new_password != confirm_password:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "new password and confirm password is not matching"},status.HTTP_400_BAD_REQUEST)
        password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
        if not re.match(password_regex, new_password):
            return Response({'status':status.HTTP_403_FORBIDDEN,'message': 'Invalid password format.'},status.HTTP_403_FORBIDDEN)
        try:
            user = Myuser.objects.get(email=email)
        except Myuser.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        if not check_password(current_password, user.password):
            return Response({'status': status.HTTP_403_FORBIDDEN, 'message': 'Current password not matching'}, status.HTTP_403_FORBIDDEN)
        if not user.is_active:
            return Response({'status': status.HTTP_403_FORBIDDEN, 'message': 'User is inactive'}, status.HTTP_403_FORBIDDEN)
        if user.is_block==True:
            return Response({'status':status.HTTP_403_FORBIDDEN,"message": "User is blocked by admin."},status.HTTP_403_FORBIDDEN)
        if user.is_valid==False:
            return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Email not verified. Please verify your email first."},status.HTTP_400_BAD_REQUEST)
        old_passwords = OldPassword_Model.objects.filter(user=user).order_by('-id')[:3]
        for password_instance in old_passwords:
            if check_password(new_password, password_instance.oldpassword):
                return Response({'status': status.HTTP_400_BAD_REQUEST,
                                 'message': 'New password should not match with last 3 passwords'},
                                status=status.HTTP_400_BAD_REQUEST)
        hash_password=make_password(new_password)
        user.password=hash_password
        user.save()
        old_password_instance = OldPassword_Model.objects.create(user=user, oldpassword=hash_password)
        old_password_instance.save()
        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)


class Logout(APIView):
    @swagger_auto_schema(
        operation_description="API for Logout user",
        operation_summary="API for Logout user",
        tags=['AUTHFLOW'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
    )
    def get(self, request):
        user = request.user
        logout(request)
        return Response({'status': status.HTTP_200_OK, 'Response': 'Logout successful'})



# get data by email
from .serializers import MyuserSerializerEdit
class ProfileDataGet(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="API used for Retrieving user profile by email",
        operation_summary="API used for Retrieving user profile by email",
        tags=['AUTHFLOW'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[""],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, default='pratap1909@mailinator.com'),
            }
        ),
    )
    def post(self, request):
        email = request.data['email']
        if email is None:
            return Response({'error': 'Email parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = Myuser.objects.get(email=email)
            serializer = MyuserSerializerEdit(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Myuser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

# update data by id
class ProfileDataUpdate(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
            operation_description="API used for updating user profile data by ID",
            operation_summary="API used for updating user profile data by ID",
            tags=['AUTHFLOW'],
            manual_parameters=[
                    openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
                    openapi.Parameter(
                        name="id",
                        in_=openapi.IN_PATH,
                        type=openapi.TYPE_INTEGER,
                        description="User's ID (primary key)",
                        required=True,
                    ),
                ],
            request_body=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                required=[],
                properties={
                    'email': openapi.Schema(type=openapi.TYPE_STRING),
                    'full_name': openapi.Schema(type=openapi.TYPE_STRING),
                    'Images': openapi.Schema(type=openapi.TYPE_FILE),
                }
            ),)
    def put(self, request,id):
            try:
                user  = Myuser.objects.get(id=id)
                serializer = MyuserSerializer(user, data=request.data,partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'status':status.HTTP_200_OK,"message": "user profile updated successfully"}, status=status.HTTP_200_OK)
                return Response({'status':status.HTTP_200_OK,"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            except Myuser.DoesNotExist:
                return Response({'status':status.HTTP_404_NOT_FOUND,"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)







# PRATAP......


# services.......................############

class Add_New_Service(APIView):
    # authentication_classes=[JWTAuthentication]
    # permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description=" This API is used Add new services",
        operation_summary="only author can new services",
        tags=['Services'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Service_Name': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
                'Service_Image': openapi.Schema(type=openapi.TYPE_FILE),
            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                service_id=random.randint(111111,999999)
                if ServiceManagementModel.objects.exists():
                    latest = ServiceManagementModel.objects.latest('sr_no')
                    sr = latest.sr_no + 1
                else:
                    sr = 1
                data = request.data
                serializer = ServiceManagementModel_serializer2(data=data)
                if serializer.is_valid():
                    serializer.save(Service_ID=service_id,sr_no=sr)
                    return Response({'status':status.HTTP_200_OK,'Response': 'Service added successfully'},status.HTTP_200_OK)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'please provide valid data'},status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #     return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class get_unique_service(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this API is Used for searched services",
        operation_summary="get unique searched services",
        tags=['Services'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Service_Name': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'start_date': openapi.Schema(type=openapi.FORMAT_DATE),
                'end_date': openapi.Schema(type=openapi.FORMAT_DATE),

            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                service_name = request.data['Service_Name']
                start_date_str = request.data['start_date']
                end_date_str = request.data['end_date']
                services = ServiceManagementModel.objects.all()
                print(start_date_str,end_date_str,"string date")
                if service_name:
                    services = services.filter(Service_Name__icontains=service_name)
                elif start_date_str and end_date_str:
                    start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
                    end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
                    end_date=end_date+timedelta(days=1)
                    # print(start_date,end_date,"dateformat")
                    services = services.filter(Created_Date_Time__gte=start_date, Created_Date_Time__lte=end_date)
                elif not services.exists():
                    return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'No services found for the given search criteria'},status.HTTP_400_BAD_REQUEST)
                serializer = ServiceManagementModel_serializer(services, many=True)
                return Response({'status':status.HTTP_200_OK,'Response': serializer.data},status.HTTP_200_OK)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class get_perticular_service(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this API is Used for get_perticular_service",
        operation_summary=" get_perticular_service",
        tags=['Services'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = ServiceManagementModel.objects.get(sr_no=id)
                serializer=ServiceManagementModel_serializer(services)
                return Response({'status':status.HTTP_200_OK,'Response': serializer.data},status.HTTP_200_OK)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)







class get_all_service(APIView):
    @swagger_auto_schema(
        operation_description="This API is used for getting all services.",
        operation_summary="Get all services",
        tags=['Services'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1',description='Provide page number'),
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10',description='Provide how many records you want'),
        ]
    )
    def get(self, request):
        try:
            user = request.user
            services = ServiceManagementModel.objects.all()
            pagination_class = CustomPageNumberPagination()
            paginated_queryset = pagination_class.paginate_queryset(queryset=services, request=request)
            serializer = ServiceManagementModel_serializer(paginated_queryset, many=True)
            return pagination_class.get_paginated_response(serializer.data)
        except Exception as e:
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class update_service(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this api is used to update services",
        operation_summary="this api is used to update services",
        tags=['Services'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Service_Name': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
                'Service_Image': openapi.Schema(type=openapi.TYPE_FILE),
            }
        ),
    )
    def put(self, request, id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                service = ServiceManagementModel.objects.get(sr_no=id)
                serializer = ServiceManagementModel_serializer2(service, data=request.data,partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'status': status.HTTP_200_OK, 'Response': 'Service updated successfully'}, status.HTTP_200_OK)
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': serializer.errors}, status.HTTP_400_BAD_REQUEST)
            except ServiceManagementModel.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'Service not found'}, status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class delete_service(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This API is used for deleting service",
        operation_summary="This API is used for deleting services",
        tags=['Services'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def delete(self,request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                service=ServiceManagementModel.objects.get(sr_no=id)
                if service:
                    service.delete()
                    return Response({'status':status.HTTP_200_OK,'Response':'deleted successfuly'},status.HTTP_200_OK)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':'this type of service doesnt exists'},status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

# Category_management_model.......................############

class get_searched_category(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this API is Used for searched _category",
        operation_summary="get unique searched _category",
        tags=['Category'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Category_name': openapi.Schema(type=openapi.TYPE_STRING, default='ATL'),
                'start_date': openapi.Schema(type=openapi.FORMAT_DATE),
                'end_date': openapi.Schema(type=openapi.FORMAT_DATE),

            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                Category_name = request.data.get('Category_name')
                start_date_str = request.data.get('start_date')
                end_date_str = request.data.get('end_date')
                categories = Category_management_model.objects.all()
                if Category_name:
                    categories = categories.filter(Category_name__icontains=Category_name)
                elif start_date_str and end_date_str:
                    start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
                    end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
                    end_date=end_date+timedelta(days=1)
                    categories = categories.filter(Created_Date_Time__gte=start_date, Created_Date_Time__lte=end_date)
                if not categories.exists():
                    return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'No Category found for the given search criteria'}, status=status.HTTP_404_NOT_FOUND)
                serializer = Category_management_model_serializer(categories, many=True)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Add_category(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description=" This API is used Add_category",
        operation_summary="only author can Add_category",
        tags=['Category'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'type': openapi.Schema(type=openapi.TYPE_STRING, default='portfolio'),
                'Category_name': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
                     }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                Category_type=request.data['type']
                if Category_management_model.objects.exists():
                    latest = Category_management_model.objects.latest('sr_no')
                    sr = latest.sr_no + 1
                else:
                    sr = 1
                serializer = Category_management_model_serializer1(data=request.data)
                if serializer.is_valid():
                    serializer.save(sr_no=sr)
                    return Response({'status':status.HTTP_200_OK,'Response': 'Service added successfully'},status.HTTP_200_OK)
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'please provide valid data'},status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class get_all_category(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description=" This API is used get_all_category",
        operation_summary="only author can get_all_category",
        tags=['Category'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
                openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1',description='Provide page number'),
                openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10',description='Provide how many records you want'),

            ],
    )
    def get(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                categories = Category_management_model.objects.all()
                pagination_class = CustomPageNumberPagination()
                paginated_queryset = pagination_class.paginate_queryset(queryset=categories, request=request)
                serializer = Category_management_model_serializer(paginated_queryset, many=True)
                return pagination_class.get_paginated_response(serializer.data)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class get_perticular_category(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description=" This API is used get_all_category",
        operation_summary="only author can get_all_category",
        tags=['Category'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                categories = Category_management_model.objects.get(sr_no=id)
                serializer = Category_management_model_serializer(categories)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class update_category(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description=" This API is used update_category",
        operation_summary="only author can update_category",
        tags=['Category'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Category_type': openapi.Schema(type=openapi.TYPE_STRING, default='portfolio'),
                'Category_name': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
            }
        ),
    )
    def put(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                data=request.data
                categories = Category_management_model.objects.get(sr_no=id)
                serializer = Category_management_model_serializer1(categories,data=data,partial=True)
                if serializer.is_valid():
                    serializer.save()
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class delete_category(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description=" This API is used delete_category",
        operation_summary="only author can delete_category",
        tags=['Category'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def delete(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                categories = Category_management_model.objects.get(sr_no=id)
                categories.delete()
                return Response({'status': status.HTTP_200_OK, 'Response':'successfuly deleted'}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

# portfolio.......................############

class get_portfolio_category(APIView):
    # authentication_classes=[JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="only author can Add get_portfolio_categoryo",
        operation_summary="only author can get_portfolio_category ",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                category = Category_management_model.objects.filter(type='portfolio')
                serializer = Category_management_model_serializer(category,many=True)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                print(e)
                return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'Response': str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Add_New_Portfolio(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="only author can Add new new_portfolio",
        operation_summary="only author can new new_portfolio use category_id to add category",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Portfolio_Category': openapi.Schema(type=openapi.TYPE_STRING, default='1'),
                'Portfolio_Name': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
                'Portfolio_Image': openapi.Schema(type=openapi.TYPE_FILE),

            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                if Portfolio_Management_model.objects.exists():
                    latest = Portfolio_Management_model.objects.latest('sr_no')
                    sr = latest.sr_no + 1
                else:
                    sr = 1
                data = request.data
                Portfolio_Category = data.get('Portfolio_Category')
                category = Category_management_model.objects.get(sr_no=Portfolio_Category)
                serializer = Portfolio_Management_model_serializer2(data=data)
                if serializer.is_valid():
                    serializer.save(Portfolio_Category=category,sr_no=sr)
                    return Response({'status': status.HTTP_201_CREATED, 'Response': 'Added new Portfolio successfully'}, status.HTTP_201_CREATED)
                else:
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response':serializer.errors }, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                print(e)
                return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'Response': str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Get_All_Portfolio(APIView):
    # authentication_classes=[JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get_All_Portfolio",
        operation_summary="Get_All_Portfolio",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
                openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1',description='Provide page number'),
                openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10',description='Provide how many records you want'),

            ],
    )
    def get(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = Portfolio_Management_model.objects.all()
                pagination_class = CustomPageNumberPagination()
                paginated_queryset = pagination_class.paginate_queryset(queryset=services, request=request)
                serializer = Portfolio_Management_model_serializer(paginated_queryset, many=True)
                return pagination_class.get_paginated_response(serializer.data)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Get_Perticular_Portfolio(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get_Perticular_Portfolio",
        operation_summary="Get_Perticular_Portfolio",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = Portfolio_Management_model.objects.get(sr_no=id)
                page=Portfolio_Management_model_serializer(services)
                return Response({'status': status.HTTP_200_OK, 'Response': page.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class GetUniquePortfolio(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get Unique Portfolio",
        operation_summary="Get Unique Portfolioget",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Portfolio_Name': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'start_date': openapi.Schema(type=openapi.FORMAT_DATE),
                'end_date': openapi.Schema(type=openapi.FORMAT_DATE),
            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                portfolio_name = request.data.get('Portfolio_Name')
                start_date_str = request.data.get('start_date')
                end_date_str = request.data.get('end_date')
                portfolios = Portfolio_Management_model.objects.all()
                if portfolio_name:
                    portfolios = portfolios.filter(Portfolio_Name__icontains=portfolio_name)
                elif start_date_str and end_date_str:
                    start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
                    end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
                    end_date=end_date+timedelta(days=1)
                    portfolios = portfolios.filter(Created_Date_Time__gte=start_date, Created_Date_Time__lte=end_date)
                elif not portfolios.exists():
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'No portfolios found for the given search criteria'}, status.HTTP_400_BAD_REQUEST)
                serializer = Portfolio_Management_model_serializer(portfolios, many=True)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class update_Portfolio(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="update_Portfolio",
        operation_summary="update_Portfolio also for update you have put category id",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Portfolio_Category_id': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
                'Portfolio_Name': openapi.Schema(type=openapi.TYPE_STRING, default='INDIA'),
                'Portfolio_Image': openapi.Schema(type=openapi.TYPE_FILE),
            }
        ),
    )
    def put(self, request, id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                data = request.data
                Portfolio_Category = data.get('Portfolio_Category_id')
                portfolio = Portfolio_Management_model.objects.get(sr_no=id)
                category = Category_management_model.objects.get(sr_no=Portfolio_Category)
                serializer = Portfolio_Management_model_serializer2(portfolio, data=data, partial=True)
                if serializer.is_valid():
                    serializer.save(Portfolio_Category=category)
                    return Response({'status': status.HTTP_200_OK, 'Response': 'Updated Portfolio successfully'}, status.HTTP_200_OK)
                else:
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'Invalid data provided'}, status.HTTP_400_BAD_REQUEST)
            except Portfolio_Management_model.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'Portfolio not found'}, status.HTTP_404_NOT_FOUND)
            except Category_management_model.DoesNotExist:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'Category not found'}, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'Response': str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class delete_portfolio(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="use this API for delete portfolio",
        operation_summary="use thsi API for delete portfolio",
        tags=['Portfolio'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def delete(self,request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                Portfolio=Portfolio_Management_model.objects.get(sr_no=id)
                Portfolio.delete()
                return Response({'status':status.HTTP_200_OK,'Response':'Portfolio deleted successfuly'},status.HTTP_200_OK)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

# blog.......................############

class get_blog_category(APIView):
    # authentication_classes=[JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this API is usede to get_blog_category",
        operation_summary="this API is used to get_blog_category",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                category = Category_management_model.objects.filter(type='blogs')
                serializer = Category_management_model_serializer(category,many=True)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                print(e)
                return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'Response': str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class GetAllBlogs(APIView):
    # authentication_classes=[JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This API is used for Getting All Blogs",
        operation_summary="This API is used for Getting All Blogs",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
                openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1',description='Provide page number'),
                openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10',description='Provide how many records you want'),

            ],
    )
    def get(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = Blog_Management_model.objects.all()
                pagination_class = CustomPageNumberPagination()
                paginated_queryset = pagination_class.paginate_queryset(queryset=services, request=request)
                serializer = Blog_Management_model_serializer(paginated_queryset, many=True)
                return pagination_class.get_paginated_response(serializer.data)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status=status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Get_unique_Blog(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This API is used to Get_unique_Blog",
        operation_summary="This API is used Get_unique_Blog",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Blog_Title': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'start_date': openapi.Schema(type=openapi.FORMAT_DATE),
                'end_date': openapi.Schema(type=openapi.FORMAT_DATE),
            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                blog_title = request.data.get('Blog_Title')
                start_date_str = request.data.get('start_date')
                end_date_str = request.data.get('end_date')
                blogs = Blog_Management_model.objects.all()
                if blog_title:
                    blogs = blogs.filter(Blog_Title__icontains=blog_title)
                elif start_date_str and end_date_str:
                    start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
                    end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
                    end_date=end_date+timedelta(days=1)
                    blogs = blogs.filter(Created_Date_Time__gte=start_date, Created_Date_Time__lte=end_date)
                elif not blogs.exists():
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'No blogs found for the given search criteria'}, status.HTTP_400_BAD_REQUEST)
                serializer = Blog_Management_model_serializer(blogs, many=True)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Get_Perticular_blogs(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get_Perticular_blogs",
        operation_summary="Get_Perticular_blogs",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = Blog_Management_model.objects.get(sr_no=id)
                page=Blog_Management_model_serializer(services)
                return Response({'status': status.HTTP_200_OK, 'Response': page.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class CreateBlog(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this API is used for CreateBlog for adding category you should put id for it",
        operation_summary="this API is used for CreateBlog",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Blog_Title': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'Blog_Category_srno': openapi.Schema(type=openapi.TYPE_STRING, default='1'),
                'Blog_Image': openapi.Schema(type=openapi.TYPE_FILE),
                'Blog_Author': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'Blog_Description': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                if Blog_Management_model.objects.exists():
                    latest = Blog_Management_model.objects.latest('sr_no')
                    sr = latest.sr_no + 1
                else:
                    sr = 1
                Blog_Category=int(request.data['Blog_Category_srno'])
                Blog_Category=Category_management_model.objects.get(sr_no=Blog_Category)
                serializer = Blog_Management_model_serializer1(data=request.data)
                if serializer.is_valid():
                    serializer.save(Blog_Category=Blog_Category,sr_no=sr)
                    return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': serializer.errors}, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':str(e)},status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class UpdateBlog(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This API is used fro Update Blog also while updating you have to put category_id",
        operation_summary="This API is used fro Update Blog also while updating you have to put category_id",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'Blog_Title': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'Blog_Category_srno': openapi.Schema(type=openapi.TYPE_STRING, default='1'),
                'Blog_Image': openapi.Schema(type=openapi.TYPE_FILE),
                'Blog_Author': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'Blog_Descrpition': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
            }
        ),
    )
    def put(self, request, id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                category_id = int(request.data['Blog_Category_srno'])
                category = Category_management_model.objects.get(sr_no=category_id)
                blog = Blog_Management_model.objects.get(sr_no=id)
                serializer = Blog_Management_model_serializer1(blog, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save(Blog_Category=category)
                    return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status=status.HTTP_200_OK)

                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            except Blog_Management_model.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'Blog not found'}, status=status.HTTP_404_NOT_FOUND)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class DeleteBlog(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This API is used to Delete_Blog",
        operation_summary="This API is used to Delete_Blog",
        tags=['Blogs'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def delete(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                blog = Blog_Management_model.objects.get(sr_no=id)
                blog.delete()
                return Response({'status': status.HTTP_200_OK, 'Response': 'Blog deleted successfully'},status.HTTP_200_OK)
            except Blog_Management_model.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'Blog not found'}, status.HTTP_404_NOT_FOUND)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

                ############ .......................Brand management.......................############

class GetAllBrands(APIView):
    # authentication_classes=[JWTAuthentication]
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This API is used for Getting All Brands",
        operation_summary="This API is used for Getting All Brands",
        tags=['Brands'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
                openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1',description='Provide page number'),
                openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10',description='Provide how many records you want'),

            ],
    )
    def get(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = Brand_management_model.objects.all()
                pagination_class = CustomPageNumberPagination()
                paginated_queryset = pagination_class.paginate_queryset(queryset=services, request=request)
                serializer = Brand_management_model_serializer(paginated_queryset, many=True)
                return pagination_class.get_paginated_response(serializer.data)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class GetSearchedBrand(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="get unique brand",
        operation_summary="get unique brand",
        tags=['Brands'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'brand_name': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'start_date': openapi.Schema(type=openapi.FORMAT_DATE),
                'end_date': openapi.Schema(type=openapi.FORMAT_DATE),

            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                brand_name = request.data.get('brand_name')
                start_date_str = request.data.get('start_date')
                end_date_str = request.data.get('end_date')
                brands = Brand_management_model.objects.all()
                if brand_name:
                    brands = brands.filter(brand_name__icontains=brand_name)
                elif start_date_str and end_date_str:
                    try:
                        start_date = datetime.datetime.strptime(start_date_str, '%Y-%m-%d')
                        end_date = datetime.datetime.strptime(end_date_str, '%Y-%m-%d')
                        end_date=end_date+timedelta(days=1)
                    except ValueError:
                        return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'Invalid date format'}, status.HTTP_400_BAD_REQUEST)
                    brands = brands.filter(Created_Date_Time__gte=start_date, Created_Date_Time__lte=end_date)
                if not brands.exists():
                    return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'No brands found for the given search criteria'}, status.HTTP_404_NOT_FOUND)
                serializer = Brand_management_model_serializer(brands, many=True)
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class Get_Perticular_brand(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Get_Perticular_brand",
        operation_summary="Get_Perticular_brand",
        tags=['Brands'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                services = Brand_management_model.objects.get(sr_no=id)
                page=Brand_management_model_serializer(services)
                return Response({'status': status.HTTP_200_OK, 'Response': page.data}, status.HTTP_200_OK)
            except Exception as e:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': str(e)}, status.HTTP_400_BAD_REQUEST)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class CreateBrand(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this api is used to CreateBrand",
        operation_summary="this api is used to CreateBrand",
        tags=['Brands'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'brand_name': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'brand_Image': openapi.Schema(type=openapi.TYPE_FILE),
            }
        ),
    )
    def post(self, request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                if Brand_management_model.objects.exists():
                    latest = Brand_management_model.objects.latest('sr_no')
                    sr = latest.sr_no + 1
                else:
                    sr = 1
                serializer = Brand_management_model_serializer2(data=request.data)
                if serializer.is_valid():
                    serializer.save(sr_no=sr)
                    return Response({'status': status.HTTP_201_CREATED, 'Response': serializer.data}, status.HTTP_201_CREATED)
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': serializer.errors}, status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status':status.HTTP_200_OK,'Response':str(e)},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)

class UpdateBrand(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="API used for Updating Brand",
        operation_summary="UpdateBrand",
        tags=['Brands'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[],
            properties={
                'brand_name': openapi.Schema(type=openapi.TYPE_STRING, default='pooja'),
                'brand_Image': openapi.Schema(type=openapi.TYPE_FILE),
            }
        ),
    )
    def put(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                Brand=Brand_management_model.objects.get(sr_no=id)
                serializer = Brand_management_model_serializer2(Brand,data=request.data,partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status.HTTP_200_OK)
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': serializer.errors}, status.HTTP_400_BAD_REQUEST)
            except Brand_management_model.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'brand not found'}, status.HTTP_404_NOT_FOUND)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)


class DeleteBrand(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="this API is used to Delete_Brand",
        operation_summary="this API is used to Delete_Brandget unique services",
        tags=['Brands'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def delete(self, request,id):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                brand = Brand_management_model.objects.get(sr_no=id)
                brand.delete()
                return Response({'status': status.HTTP_200_OK, 'Response': 'Brand deleted successfully'}, status.HTTP_200_OK)
            except Brand_management_model.DoesNotExist:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'Brand not found'}, status.HTTP_404_NOT_FOUND)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)


class Dashboard(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="The Dashboard API provides a comprehensive overview of key metrics for the PortfolioHub platform. Accessible only to authenticated users with administrative privileges, the API delivers information on the total number of blogs, brands, services, and portfolios available on the platform. Additionally, it provides a list of portfolios, ordered by their creation date and time. The response includes detailed statistics, empowering administrators to efficiently monitor and manage content across different categories within the PortfolioHub ecosystem.",
        operation_summary="this API is used to Dashboard view",
        tags=['Dashboard'],
        manual_parameters=[
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
    )
    def get(self,request):
        try:
            user=request.user
            # if user.role=='admin':
            try:
                Total_Blogs=Blog_Management_model.objects.all().count()
                Total_Brands=Brand_management_model.objects.all().count()
                Total_Services=ServiceManagementModel.objects.all().count()
                Total_Portfolio=Portfolio_Management_model.objects.all().count()
                portfolios_list = Portfolio_Management_model.objects.all().order_by('-Created_Date_Time')
                serializer = Portfolio_Management_model_serializer(portfolios_list, many=True)
                if serializer:
                    return Response({'status': status.HTTP_200_OK,'portfolios_list':serializer.data ,'Total_Blogs':Total_Blogs,'Total_Brands':Total_Brands,'Total_Services':Total_Services,'Total_Portfolio':Total_Portfolio}, status.HTTP_200_OK)
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': 'this details only accessible to admin'}, status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({'status': status.HTTP_404_NOT_FOUND, 'Response': str(e)}, status.HTTP_404_NOT_FOUND)
            # else:
            #         return Response({'status':status.HTTP_400_BAD_REQUEST,'Response': 'only admin can access It'},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_400_BAD_REQUEST,'Reaponse': str(e)},status.HTTP_400_BAD_REQUEST)


class StaticContentView_terms(APIView):
    @swagger_auto_schema(
        operation_description="Get Terms and Conditions",
        operation_summary="Get Terms and Conditions",
        tags=['StaticContent'],
        responses={
            200: "Terms and Conditions retrieved successfully",
            404: "Terms and Conditions not found",
            400: "Invalid data"
        }
    )
    def get(self, request):
        try:
            title = 'Terms and Conditions'
            content_instance = static_content.objects.get(title=title)
            serializer = Static_ContentSerializer(content_instance)  # Pass the instance, not data
            return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status=status.HTTP_200_OK)
        except static_content.DoesNotExist:
            return Response({"message": "Terms and Conditions not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Update Terms and Conditions",
        operation_summary="Update Terms and Conditions",
        tags=['StaticContent'],
        manual_parameters=
        [
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        request_body=Static_ContentSerializer,
        responses={
            200: "Terms and Conditions updated successfully",
            400: "Invalid data"
        }
    )
    def put(self, request):
        try:
            title = 'Terms and Conditions'
            content_instance = static_content.objects.get(title=title)
            serializer = Static_ContentSerializer(content_instance, data=request.data,partial=True)
            if serializer.is_valid():
                serializer.save()  # Save the updated content
                return Response({"message": "Terms and Conditions updated successfully"}, status=status.HTTP_200_OK)
            return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
        except static_content.DoesNotExist:
            return Response({"message": "Terms and Conditions not found"}, status=status.HTTP_404_NOT_FOUND)


class StaticContentView_privacy(APIView):
        @swagger_auto_schema(
        operation_description="Get Privacy And Policy",
        operation_summary="Get Privacy And Policy",
        tags=['StaticContent'],
        responses={
            200: "Privacy And Policy retrieved successfully",
            404: "Privacy And Policy not found",
            400: "Invalid data"
        }
        )
        def get(self, request):
            try:
                title = 'Privacy And Policy'
                content_instance = static_content.objects.get(title=title)
                serializer = Static_ContentSerializer(content_instance)  # Pass the instance, not data
                return Response({'status': status.HTTP_200_OK, 'Response': serializer.data}, status=status.HTTP_200_OK)
            except static_content.DoesNotExist:
                return Response({"message": "Privacy And Policy not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

        @swagger_auto_schema(
            operation_description="Update Privacy And Policy",
            operation_summary="Update Privacy And Policy",
            tags=['StaticContent'],
            manual_parameters=
            [
                openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
            ],
            request_body=Static_ContentSerializer,
            responses={
                200: "Privacy And Policy updated successfully",
                400: "Invalid data"
            }
        )
        def put(self, request):
            try:
                title = 'Privacy And Policy'
                content_instance = static_content.objects.get(title=title)
                serializer = Static_ContentSerializer(content_instance, data=request.data,partial=True)
                if serializer.is_valid():
                    serializer.save()  # Save the updated content
                    return Response({"message": "Privacy And Policy updated successfully"}, status=status.HTTP_200_OK)
                return Response({"message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
            except static_content.DoesNotExist:
                return Response({"message": "Privacy And Policy not found"}, status=status.HTTP_404_NOT_FOUND)



class AddFAQView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="ADD FAQ",
        operation_summary="ADD FAQ",
        manual_parameters=
        [
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['StaticContent'],
        request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
            properties={
                'question': openapi.Schema(type=openapi.TYPE_STRING),
                'answer': openapi.Schema(type=openapi.TYPE_STRING)
            }
        )
    )
    def post(self, request):
        serializer = FAQSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "FAQ added successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetAllFAQView(APIView):
    @swagger_auto_schema(
        operation_description="get all FAQ",
        operation_summary="get all FAQ",
        manual_parameters=
        [
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING)
        ],
        tags=['StaticContent'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
        )
    )
    def get(self, request):
        faqs = FAQ.objects.all()
        serializer = FAQSerializer(faqs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    pagination_class = CustomPageNumberPagination
    @swagger_auto_schema(
        operation_description="Search and Filter FAQs",
        operation_summary="Search and Filter FAQs",
        tags=['StaticContent'],
        manual_parameters=[
            openapi.Parameter('q', openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Search FAQs by keyword", required=False),
            openapi.Parameter('from_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, format='date', description="Filter FAQs from a specific date (YYYY-MM-DD)", required=False),
            openapi.Parameter('to_date', openapi.IN_QUERY, type=openapi.TYPE_STRING, format='date', description="Filter FAQs until a specific date (YYYY-MM-DD)", required=False),
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1',description='Provide page number'),
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10',description='Provide how many records you want'),

        ],
        responses={
            status.HTTP_200_OK: "FAQs retrieved successfully",
            status.HTTP_400_BAD_REQUEST: "Invalid query parameters"
        }
    )
    def get(self, request):
        query = request.query_params.get('q', '')
        from_date = request.query_params.get('from_date', '')
        to_date = request.query_params.get('to_date', '')
        queryset = FAQ.objects.all()
        if query:
            queryset = queryset.filter(Q(question__icontains=query) | Q(answer__icontains=query))
        if from_date:
            try:
                from_date = parse_date(from_date)
                start_datetime = timezone.make_aware(timezone.datetime(from_date.year, from_date.month, from_date.day))
                queryset = queryset.filter(created_at__gte=start_datetime)
            except ValueError:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'Invalid from_date format'}, status=status.HTTP_400_BAD_REQUEST)
        if to_date:
            try:
                to_date = parse_date(to_date)
                end_datetime = timezone.make_aware(timezone.datetime(to_date.year, to_date.month, to_date.day, 23, 59, 59, 999999))
                queryset = queryset.filter(created_at__lte=end_datetime)
            except ValueError:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'Response': 'Invalid to_date format'}, status=status.HTTP_400_BAD_REQUEST)
        pagination_class = CustomPageNumberPagination()
        paginated_queryset = pagination_class.paginate_queryset(queryset=queryset, request=request)
        serializer = FAQSerializer(paginated_queryset, many=True)
        return pagination_class.get_paginated_response(serializer.data)


class FAQDelete(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Delete a FAQ by sr_no",
        operation_summary="Delete a FAQ by sr_no",
        tags=['StaticContent'],
        manual_parameters=
        [
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        
    )
    def delete(self,request,id):
        try:
            faq = FAQ.objects.get(sr_no=id)
            faq.delete()
            return Response({"message": "FAQ  deleted"}, status=status.HTTP_200_OK)
        except FAQ.DoesNotExist:
            return Response({"message": "FAQ not found"}, status=status.HTTP_404_NOT_FOUND)


class getPerticularFAQ(APIView):
    @swagger_auto_schema(
        operation_description="this API is for view_FAQs get by id",
        operation_summary="this API is for view_FAQs get by id",
        tags=['StaticContent'],
    )
    def get(self, request,id):
        try:
            use=request.user
            try:
                FAq=FAQ.objects.get(sr_no=id)
                serialize=FAQSerializer(FAq)
                return Response({'status':status.HTTP_200_OK,'Response':serialize.data},status.HTTP_200_OK)
            except Exception as e:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'Response':str(e)},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_404_NOT_FOUND,'Response':str(e)},status.HTTP_404_NOT_FOUND)

