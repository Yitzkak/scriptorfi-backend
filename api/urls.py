from django.urls import path
from api.views import RegisterView, CustomTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView
from .views import UserFileListView, UpdateFileStatusView, FileUploadView, DeleteFileStatusView

urlpatterns = [
    path('users/register/', RegisterView.as_view(), name='register'),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Custom login
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/logout/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('files/', UserFileListView.as_view(), name='user_file_list'),
    path('files/<int:pk>/', UpdateFileStatusView.as_view(), name='update_file_status'),
    path('files/upload/', FileUploadView.as_view(), name='file_upload'),
    path('files/<int:pk>/delete/', DeleteFileStatusView.as_view(), name='delete_file'),
]