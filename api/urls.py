from django.urls import path
from api.views import RegisterView, CustomTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView
from .views import (
    UserFileListView,
    UpdateFileStatusView,
    FileUploadView,
    DeleteFileStatusView, SuperAdminLoginView,
    AdminFileListView, get_notifications, mark_notification_as_read,
    UserProfileView, UpdateProfileView, UpdatePasswordView,
    AnonymousFileUploadView, ClaimUploadView,
    UserTranscriptionListView, TranscriptDetailView, AdminUploadTranscriptView,
    ContactSupportView,
    PasswordResetRequestView,
    PasswordResetConfirmView
)
from .payment_views import (
    CreatePaymentView,
    ExecutePaymentView,
    CheckPaymentStatusView,
    CreateBatchPaymentView,
    ExecuteBatchPaymentView,
    CreatePaystackPaymentView,
    VerifyPaystackPaymentView,
    PaystackWebhookView,
    PayPalWebhookView
)

urlpatterns = [
    path('superadmin/login/', SuperAdminLoginView.as_view(), name='superadmin_login'),
    path('superadmin/files/', AdminFileListView.as_view(), name='superadmin_file_list'),
    path('superadmin/files/<int:pk>/status/', UpdateFileStatusView.as_view(), name='update_file_status'),      
    path('users/register/', RegisterView.as_view(), name='register'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Custom login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/logout/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('files/', UserFileListView.as_view(), name='user_file_list'),
    path('files/<int:pk>/', UpdateFileStatusView.as_view(), name='update_file_status'),
    path('files/upload/', FileUploadView.as_view(), name='file_upload'),
    path('files/upload/anonymous/', AnonymousFileUploadView.as_view(), name='anonymous_file_upload'),
    path('files/claim/', ClaimUploadView.as_view(), name='claim_upload'),
    path('files/<int:pk>/delete/', DeleteFileStatusView.as_view(), name='delete_file'),
    path('transcriptions/', UserTranscriptionListView.as_view(), name='user_transcription_list'),
    path('transcriptions/<int:file_id>/', TranscriptDetailView.as_view(), name='transcript_detail'),
    path('superadmin/files/<int:file_id>/transcript/', AdminUploadTranscriptView.as_view(), name='admin_upload_transcript'),
    path('notifications/', get_notifications, name='get_notifications'),
    path('notifications/<int:pk>/read/', mark_notification_as_read, name='mark_notification_as_read'),
    path('user-profile/', UserProfileView.as_view(), name='user_profile'),
    path('update-profile/', UpdateProfileView.as_view(), name='update-profile'),
    path('update-password/', UpdatePasswordView.as_view(), name='update-password'),
    path('contact/', ContactSupportView.as_view(), name='contact-support'),
    path('auth/password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('auth/password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    
    # Payment URLs
    path('payment/create/', CreatePaymentView.as_view(), name='create_payment'),
    path('payment/create-batch/', CreateBatchPaymentView.as_view(), name='create_payment_batch'),
    path('payment/execute/', ExecutePaymentView.as_view(), name='execute_payment'),
    path('payment/execute-batch/', ExecuteBatchPaymentView.as_view(), name='execute_payment_batch'),
    path('payment/status/<int:file_id>/', CheckPaymentStatusView.as_view(), name='check_payment_status'),
    path('payment/paystack/initialize/', CreatePaystackPaymentView.as_view(), name='paystack_initialize'),
    path('payment/paystack/verify/', VerifyPaystackPaymentView.as_view(), name='paystack_verify'),
    path('payment/paystack/webhook/', PaystackWebhookView.as_view(), name='paystack_webhook'),
    path('payment/paypal/webhook/', PayPalWebhookView.as_view(), name='paypal_webhook'),
]
