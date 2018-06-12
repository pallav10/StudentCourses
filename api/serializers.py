from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers
from rest_framework.authtoken.models import Token

from models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "confirm_password")

    def create(self, validated_data):
        del validated_data["confirm_password"]
        return super(UserRegistrationSerializer, self).create(validated_data)

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('confirm_password'):
            raise serializers.ValidationError("Those passwords don't match.")
        return attrs


class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    default_error_messages = {
        'inactive_account': _('User account is disabled.'),
        'invalid_credentials': _('Unable to login with provided credentials.')
    }

    def __init__(self, *args, **kwargs):
        super(UserLoginSerializer, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self, attrs):
        self.user = authenticate(
            username=attrs.get("email"),
            password=attrs.get('password'))
        if self.user:
            if not self.user.is_active:
                raise serializers.ValidationError(
                    self.error_messages['inactive_account'])
            return attrs
        else:
            raise serializers.ValidationError(
                self.error_messages['invalid_credentials'])


# serialize data of user for common need of user table.
class UserProfileSerializer(serializers.ModelSerializer):
    contact_no = serializers.IntegerField(required=False)

    class Meta:
        model = User
        fields = (
            'email', 'id', 'username',
            'created', 'country_code', 'contact_no', 'city',
            'state', 'country', 'is_password_changed')


class TokenSerializer(serializers.ModelSerializer):
    auth_token = serializers.CharField(source='key')

    class Meta:
        model = Token
        fields = ("auth_token",)
