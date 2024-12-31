from rest_framework import serializers
from .models import UploadedFile
from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.contrib.auth import get_user_model

CustomUser = get_user_model()  # This will use the CustomUser model

## Custom User Serializer
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username']

## Register user serilizer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = CustomUser
        fields = ['email', 'password', 'confirm_password']

    def validate(self, data):
        # Check if passwords match
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        
        # Ensure the email is unique
        if CustomUser.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({"email": "A user with this email already exists."})
        
        return data

    def create(self, validated_data):
        # Remove confirm_password as it's not part of the CustomUser model
        validated_data.pop('confirm_password')
        
        # Create username from email (or handle unique username generation)
        username = validated_data.get('email', '').split('@')[0]
        
        if CustomUser.objects.filter(username=username).exists():
            raise ValidationError({"username": "Username already exists."})
        
        # Create user with hashed password
        user = CustomUser.objects.create_user(
            username=username,
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

## Uploaded files  Serializer 
class FileSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer();
    class Meta:
        model = UploadedFile
        fields = ["id", "name", "size", "file", "date_uploaded", "status", "user"]