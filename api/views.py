from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import (
    RegisterSerializer, 
    FileSerializer, NotificationSerializer, 
    UpdateProfileSerializer, UpdatePasswordSerializer,
    TranscriptSerializer,
    ContactSupportSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)
from django.conf import settings
from decimal import Decimal, ROUND_HALF_UP
from .tokens import generate_confirmation_token  
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.generics import ListAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView
from django.http import JsonResponse
from .models import UploadedFile, CustomUser, Notification, Transcript
from rest_framework.permissions import IsAuthenticated  
from rest_framework.decorators import api_view, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from rest_framework.permissions import BasePermission
from django.contrib.auth.password_validation import validate_password
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model


##### Functions for sending notifications
def create_notification_for_admins(file, user):
    admins = CustomUser.objects.filter(is_staff=True)
    for admin in admins:
        Notification.objects.create(
            user=admin,
            message=f"A new file '{file.name}' has been uploaded by {user.username}."
        )
        
def create_notification_for_customer(file, status):
    Notification.objects.create(
        user=file.user,
        message=f"Your file '{file.name}' has been marked as {status}."
    )


def _parse_duration_seconds(value):
    try:
        if value is None:
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _compute_cost_seconds(duration_seconds):
    per_minute = Decimal(str(getattr(settings, "TRANSCRIPTION_PRICE_PER_MINUTE", "0.60")))
    cost = (Decimal(duration_seconds) / Decimal(60)) * per_minute
    return cost.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _validate_upload(file_obj):
    max_mb = int(getattr(settings, "MAX_UPLOAD_MB", 200))
    max_bytes = max_mb * 1024 * 1024
    if file_obj.size > max_bytes:
        return False, f"File size exceeds {max_mb}MB"

    allowed_types = set(getattr(settings, "ALLOWED_UPLOAD_MIME_TYPES", []))
    if allowed_types and file_obj.content_type not in allowed_types:
        return False, "Unsupported file type"

    return True, None

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
    permission_classes = [IsSuperAdmin]

    def post(self, request, pk):
        try:
            uploaded_file = UploadedFile.objects.get(pk=pk)
            status = request.data.get("status")
            if status in dict(UploadedFile.STATUS_CHOICES).keys():
                uploaded_file.status = status
                uploaded_file.save()
                if status == "Completed":
                    create_notification_for_customer(uploaded_file, status)
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


class UserTranscriptionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        files = UploadedFile.objects.filter(user=request.user, status="Completed")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data)


class TranscriptDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, file_id):
        uploaded_file = get_object_or_404(UploadedFile, id=file_id, user=request.user)
        transcript = getattr(uploaded_file, "transcript", None)
        if not transcript:
            return Response({"error": "Transcript not available"}, status=404)
        serializer = TranscriptSerializer(transcript)
        return Response(serializer.data)


class AdminUploadTranscriptView(APIView):
    permission_classes = [IsSuperAdmin]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, file_id):
        uploaded_file = get_object_or_404(UploadedFile, id=file_id)
        transcript_text = request.data.get("transcript_text")
        transcript_file = request.FILES.get("transcript_file")

        if not transcript_text and not transcript_file:
            return Response({"error": "transcript_text or transcript_file is required"}, status=400)

        transcript, _created = Transcript.objects.get_or_create(uploaded_file=uploaded_file)
        if transcript_text:
            transcript.text = transcript_text
        if transcript_file:
            transcript.file = transcript_file
        transcript.save()

        uploaded_file.status = "Completed"
        uploaded_file.save(update_fields=["status"])
        create_notification_for_customer(uploaded_file, "Completed")

        serializer = TranscriptSerializer(transcript)
        return Response(serializer.data, status=200)
    
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

### Register User view
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

# Function for uploading files
class FileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    
    def post(self, request, *args, **kwargs):
        print(request.data)
        file = request.FILES.get('file')
        
        if not file:
            print("File not right", file)
            return Response({"error": "No file uploaded."}, status=status.HTTP_400_BAD_REQUEST)

        is_valid, error_message = _validate_upload(file)
        if not is_valid:
            return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)
        
        duration_seconds = _parse_duration_seconds(request.data.get("size"))
        free_trial = str(request.data.get("free_trial", "")).lower() == "true"

        if free_trial:
            if request.user.free_trial_used:
                return Response({"error": "Free trial already used"}, status=status.HTTP_400_BAD_REQUEST)
            # Limit transcription to first 5 minutes
            duration_seconds = min(duration_seconds, int(getattr(settings, "FREE_TRIAL_SECONDS", 300)))
        if duration_seconds <= 0:
            return Response({"error": "Invalid duration"}, status=status.HTTP_400_BAD_REQUEST)

        additional_info = request.data.get("instruction")
        if free_trial:
            note = "Free trial: transcribe first 5 minutes only."
            additional_info = f"{note} {additional_info}".strip() if additional_info else note

        total_cost = Decimal("0.00") if free_trial else _compute_cost_seconds(duration_seconds)
        payment_status = "Paid" if total_cost == Decimal("0.00") else "Unpaid"

        data = {
            "name": file.name,
            "size": duration_seconds,
            "file": file,
            "status": "Pending",
            "total_cost": total_cost,
            "verbatim": request.data.get("verbatim"),
            "rush_order": request.data.get("rush_order"),
            "timestamp": request.data.get("timestamp"),
            "spelling": request.data.get("spelling"),
            "additional_info": additional_info,
            "payment_status": payment_status
        }

        
        serializer = FileSerializer(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            if free_trial:
                request.user.free_trial_used = True
                request.user.save(update_fields=["free_trial_used"])
            ## create a new file notification
            create_notification_for_admins(file, request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Function to delete a file
class DeleteFileStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk, *args, **kwargs):
        file = get_object_or_404(UploadedFile, pk=pk, user=request.user)
        file.file.delete()  # Delete the actual file from storage
        file.delete()  # Delete the database record
        return Response({"message": "File deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
    
## Notification View
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_notifications(request):
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    serializer = NotificationSerializer(notifications, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_notification_as_read(request, pk):
    try:
        notification = Notification.objects.get(id=pk, user=request.user)
        notification.read = True
        notification.save()
        return Response({'message': 'Notification marked as read'})
    except Notification.DoesNotExist:
        return Response({'error': 'Notification not found'}, status=404)

#### User Profile View
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = UpdateProfileSerializer(user)
        return Response(serializer.data)
    
### Update User Profile
class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = UpdateProfileSerializer(instance=request.user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile updated successfully."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

### Update User Password
class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        print("data:", request.data)
        serializer = UpdatePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not request.user.check_password(serializer.validated_data['old_password']):
                return Response({"old_password": "Incorrect password."}, status=status.HTTP_400_BAD_REQUEST)
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()
            return Response({"message": "Password updated successfully."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


### Anonymous File Upload (for public upload page)
class AnonymousFileUploadView(APIView):
    permission_classes = [AllowAny]
    parser_classes = (MultiPartParser, FormParser)
    
    def post(self, request, *args, **kwargs):
        file = request.FILES.get('file')
        
        if not file:
            return Response({"error": "No file uploaded."}, status=status.HTTP_400_BAD_REQUEST)

        is_valid, error_message = _validate_upload(file)
        if not is_valid:
            return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)
        
        duration_seconds = _parse_duration_seconds(request.data.get("size"))
        if duration_seconds <= 0:
            return Response({"error": "Invalid duration"}, status=status.HTTP_400_BAD_REQUEST)

        total_cost = _compute_cost_seconds(duration_seconds)
        payment_status = "Paid" if total_cost == Decimal("0.00") else "Unpaid"

        data = {
            "name": file.name,
            "size": duration_seconds,
            "file": file,
            "status": "Pending",
            "total_cost": total_cost,
            "verbatim": request.data.get("verbatim"),
            "rush_order": request.data.get("rush_order"),
            "timestamp": request.data.get("timestamp"),
            "spelling": request.data.get("spelling"),
            "additional_info": request.data.get("instruction"),
            "payment_status": payment_status
        }
        
        serializer = FileSerializer(data=data)
        if serializer.is_valid():
            # Save without user - this creates an anonymous upload
            uploaded_file = serializer.save()
            return Response({
                "id": uploaded_file.id,
                "message": "File uploaded successfully",
                **serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


### Claim Anonymous Upload (associate with logged-in user)
class ClaimUploadView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        upload_id = request.data.get('upload_id')
        upload_ids = request.data.get('upload_ids')

        if not upload_id and not upload_ids:
            return Response({"error": "upload_id or upload_ids is required"}, status=status.HTTP_400_BAD_REQUEST)

        ids = []
        if upload_ids and isinstance(upload_ids, list):
            ids = upload_ids
        elif upload_id:
            ids = [upload_id]

        claimed = []
        for file_id in ids:
            try:
                uploaded_file = UploadedFile.objects.get(id=file_id)
                if uploaded_file.user is None:
                    uploaded_file.user = request.user
                    uploaded_file.save()
                    create_notification_for_admins(uploaded_file, request.user)
                elif uploaded_file.user != request.user:
                    return Response({"error": "Upload belongs to another user"}, status=status.HTTP_403_FORBIDDEN)
                claimed.append(uploaded_file.id)
            except UploadedFile.DoesNotExist:
                return Response({"error": "Upload not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "message": "Upload claimed successfully",
            "file_ids": claimed
        }, status=status.HTTP_200_OK)


class ContactSupportView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = ContactSupportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        support_email = getattr(settings, "SUPPORT_EMAIL", "support@scriptorfi.com")
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or support_email

        subject = f"Support request from {data['name']}"
        body = (
            f"Name: {data['name']}\n"
            f"Email: {data['email']}\n\n"
            "Message:\n"
            f"{data['message']}"
        )

        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=from_email,
            to=[support_email],
            reply_to=[data["email"]],
        )
        email.send(fail_silently=False)

        return Response({"message": "Message sent successfully."}, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"].lower()
        UserModel = get_user_model()
        user = UserModel.objects.filter(email=email).first()

        if user:
            token_generator = PasswordResetTokenGenerator()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)
            frontend_base = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:3000")
            reset_link = f"{frontend_base}/reset-password?uid={uid}&token={token}"

            subject = "Reset your Scriptorfi password"
            body = (
                "We received a request to reset your password.\n\n"
                f"Reset your password using the link below:\n{reset_link}\n\n"
                "If you did not request this, you can ignore this email."
            )

            email_message = EmailMessage(
                subject=subject,
                body=body,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None) or getattr(settings, "SUPPORT_EMAIL", "support@scriptorfi.com"),
                to=[email],
            )
            email_message.send(fail_silently=False)

        return Response({"message": "If that email exists, a reset link has been sent."}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            UserModel = get_user_model()
            user = UserModel.objects.get(pk=user_id)
        except (ValueError, TypeError, UserModel.DoesNotExist):
            return Response({"error": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired reset link."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password, user)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)




























