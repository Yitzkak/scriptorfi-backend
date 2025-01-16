from django.urls import path
from api.views import RegisterView, CustomTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView
from .views import (
    UserFileListView, 
    UpdateFileStatusView,
    FileUploadView, 
    DeleteFileStatusView, SuperAdminLoginView, 
    AdminFileListView, get_notifications, mark_notification_as_read,
    UserProfileView, UpdateProfileView, UpdatePasswordView
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
    path('files/<int:pk>/delete/', DeleteFileStatusView.as_view(), name='delete_file'),
    path('notifications/', get_notifications, name='get_notifications'),
    path('notifications/<int:pk>/read/', mark_notification_as_read, name='mark_notification_as_read'),
    path('user-profile/', UserProfileView.as_view(), name='user_profile'),
    path('update-profile/', UpdateProfileView.as_view(), name='update-profile'),
    path('update-password/', UpdatePasswordView.as_view(), name='update-password'),
    
]