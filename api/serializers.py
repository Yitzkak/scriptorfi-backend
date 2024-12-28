from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UploadedFile
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ['email', 'password', 'confirm_password']

    def validate(self, data):
        # Check if passwords match
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        # Remove confirm_password as it's not part of the User model
        validated_data.pop('confirm_password')
        user = User.objects.create_user(
            username=validated_data.get('email', '').split('@')[0],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ["id", "name", "size", "file", "date_uploaded", "status"]