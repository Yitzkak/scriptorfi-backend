import uuid
from rest_framework import serializers
from .models import UploadedFile
from django.core.exceptions import ValidationError
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Notification

CustomUser = get_user_model()  # This will use the CustomUser model

## Custom User Serializer
class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username' ]

## Register user serilizer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'country', 'password', 'confirm_password']

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
        username = f"user_{uuid.uuid4().hex[:8]}"  # e.g., "user_1234abcd"
        
        if CustomUser.objects.filter(username=username).exists():
            raise ValidationError({"username": "Username already exists."})
        
        # Create user
        user = CustomUser.objects.create_user(
            username=username,
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            country=validated_data['country']
        )
        return user

## Uploaded files  Serializer 
class FileSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True);
    total_cost = serializers.IntegerField()
    class Meta:
        model = UploadedFile
        fields = ["id", "name", "size", "file", "date_uploaded", "status", "user", "total_cost", "verbatim", "rush_order", "timestamp", "spelling", "additional_info"]
        
## Notifications Serializer
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'user', 'message', 'created_at', 'read']

## Update User Serializer
class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'country', 'first_name', 'last_name']

class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return data
