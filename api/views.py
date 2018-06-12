import re

from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.authentication import BasicAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from serializers import UserRegistrationSerializer
from permissions import UserPermissions
import utils
import validations_utils
import messages
from validations_utils import ValidationException


class UserRegistrationAPIView(CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserRegistrationSerializer

    def create(self, request, *args, **kwargs):
        data = validations_utils.email_validation(
            request.data)  # Validates email id, it returns lower-cased email in data.
        data = validations_utils.password_validation(data)  # Validates password criteria.
        data['password'] = data['confirm_password'] = utils.hash_password(data['password'])
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = serializer.instance
        token, created = Token.objects.get_or_create(user=user)
        data = serializer.data
        data["token"] = token.key

        headers = self.get_success_headers(serializer.data)
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)


class UserLoginAPIView(APIView):
    authentication_classes = [BasicAuthentication]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
            **User Login**

            Login an existing user.

            Used for authenticating the user.

            > POST

            * Requires following fields of users in JSON format:

                1. `email` - String
                2. `password` - String

            * Returns user profile data on successful login.
            * Also returns Authentication token to be used by frontend for further
             communication with backend.
            * On failure it returns appropriate HTTP status and message in JSON
            response.

            * Possible HTTP status codes and JSON response:

                * `HTTP_200_OK` on successful login.

                * `HTTP_401_UNAUTHORIZED` for failed login attempt.

                        {
                         "message": "Invalid username or password"
                        }

                * `HTTP_500_INTERNAL_SERVER_ERROR` - Internal server error.

                * `HTTP_404_NOT_FOUND` - When user is not found.

                        {
                         "message": "User with specified email does not exist."
                        }
            :param request:
            """
        try:
            email = request.data['email']
            password = request.data['password']
        except KeyError:
            return Response(
                messages.REQUIRED_EMAIL_AND_PASSWORD,
                status=status.HTTP_400_BAD_REQUEST)
        try:
            # response = validations_utils.login_user_existence_validation(email)
            user = authenticate(email=email, password=password)  # Validates credentials of user.
        except ValidationException:
            return Response(messages.INVALID_EMAIL_OR_PASSWORD, status=status.HTTP_401_UNAUTHORIZED)
        try:
            # Authorizes the user and returns appropriate data.
            login_user = utils.authenticate_user(user, request.data)
            # token = utils.fetch_token(user)  # fetches the token for authorized user.
        except ValidationException as e:  # Generic exception
            return Response(e.errors, status=e.status)
        return Response(login_user, status=status.HTTP_200_OK)


class UserLogoutAPIView(APIView):
    def post(self, request, *args, **kwargs):
        Token.objects.filter(user=request.user).delete()
        return Response(status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    permission_classes = [UserPermissions, IsAuthenticated]

    def put(self, request):
        """
        ### Change Password
        * While changing password for user registered with email, PUT request
        requires two fields and their values:
            * current_password - String
            * new_password - String
        * Possible HTTP status codes and JSON response:
            * `HTTP_200_OK` - If password change was successful:
                    {
                     "user_id": integer,
                     "message": "Password updated successfully"
                    }
            * `HTTP_401_UNAUTHORIZED` - If user provided incorrect value for
            current_password:
                    {
                     "message": "Current password is incorrect."
                    }
            * `HTTP_400_BAD_REQUEST` - If new_password is same as current_password:
                    {
                     "message": "New password cannot be same as current password"
                    }
            * `HTTP_500_INTERNAL_SERVER_ERROR` - Internal server error
            :param pk:
            :param request:
        """
        # try:
        #     user = validations_utils.user_validation(pk)  # Validates if user exists or not.
        #     validations_utils.user_token_validation(
        #         request.auth.user_id, pk)  # Validates user's Token authentication.
        # except ValidationException as e:  # Generic exception
        #     return Response(e.errors, status=e.status)
        try:
            request.data['current_password']
        except KeyError:
            return Response(messages.REQUIRED_CURRENT_PASSWORD,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            new_password = request.data['new_password']
            if new_password is None or not re.match(
                    r'[A-Za-z0-9@#$%^&+=]+', new_password):
                return Response(messages.PASSWORD_NECESSITY,
                                status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                pass
        except KeyError:
            return Response(
                messages.REQUIRED_NEW_PASSWORD,
                status=status.HTTP_400_BAD_REQUEST)
        data_keys = request.data.keys()
        # Change Password will only require current_password and new_password.
        if 'current_password' in data_keys and 'new_password' in data_keys:
            current_password = request.data['current_password']
            new_password = request.data['new_password']
            try:
                password = utils.change_password(
                    current_password, new_password, request.user)  # Changes password.
                return Response(password, status=status.HTTP_200_OK)
            except ValidationException as e:
                return Response(e.errors, status=e.status)
