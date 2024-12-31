from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterSerializer, FileSerializer
from django.conf import settings
from .tokens import generate_confirmation_token  # You'd create this token generator
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.generics import ListAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView
from django.http import JsonResponse
from .models import UploadedFile, CustomUser
from rest_framework.permissions import IsAuthenticated  
from rest_framework.decorators import api_view
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from rest_framework.permissions import BasePermission

## Permission check for super admin users
class IsSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and getattr(request.user, 'is_super_admin', False)

## Login for super admin access
class SuperAdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        ## Check if user is authenticated
        user = authenticate(username=email, password=password)
        print("User object:", user)
        
        ## Check if user is a super admin user
        if user and user.is_super_admin:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Login successful'
            }, status=200)

        return Response({'error': 'Invalid credentials or not a Super Admin'}, status=401)

## View for updating file status
class UpdateFileStatusView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        try:
            uploaded_file = UploadedFile.objects.get(pk=pk)
            status = request.data.get("status")
            if status in dict(UploadedFile.STATUS_CHOICES).keys():
                uploaded_file.status = status
                uploaded_file.save()
                return Response({"message": "Status updated successfully"}, status=200)
            else:
                return Response({"error": "Invalid status value"}, status=400)
        except UploadedFile.DoesNotExist:
            return Response({"error": "File not found"}, status=404)

## Super Admin file list view
class AdminFileListView(ListAPIView):
    permission_classes = [IsSuperAdmin]
    queryset = UploadedFile.objects.all()
    serializer_class = FileSerializer
    
### Login for user
class CustomTokenObtainPairView(TokenObtainPairView):

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")
        
        if email and password:
            # Use CustomUser model to authenticate by email
            try:
                user = CustomUser.objects.get(email=email)
                if user.check_password(password):
                    # If the password is correct, generate JWT tokens
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    })
                else:
                    return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            except CustomUser.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # Create user instance
            return Response({"message": "Registration successful. Please check your email for confirmation."}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Function for getting files
class UserFileListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        files = UploadedFile.objects.filter(user=request.user)
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data)

## Function for updting file status

    
# Function for uploading files
class FileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    def post(self, request, *args, **kwargs):
        print(request.data)
        file = request.FILES.get('file')
        
        if not file:
            return Response({"error": "No file uploaded."}, status=status.HTTP_400_BAD_REQUEST)
        
        data = {
            "name": file.name,
            "size": file.size,
            "file": file,
            "status": "Pending"  # Set initial status as pending until processing is complete.
        }
        
        serializer = FileSerializer(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Function to delete a file
class DeleteFileStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk, *args, **kwargs):
        file = get_object_or_404(UploadedFile, pk=pk, user=request.user)
        file.file.delete()  # Delete the actual file from storage
        file.delete()  # Delete the database record
        return Response({"message": "File deleted successfully"}, status=status.HTTP_204_NO_CONTENT)