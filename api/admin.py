from django.contrib import admin
from .models import UploadedFile
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

# Customize the admin for your CustomUser model if needed
@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    # Define the fields to display in the admin
    model = CustomUser
    list_display = ('username','email', 'is_superuser', 'is_super_admin','is_staff')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_super_admin')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_staff', 'is_superuser'),
        }),
    )

@admin.register(UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    # Fields to display as columns
    list_display = ('id', 'name', 'size', 'date_uploaded', 'status', 'user')

    # Fields that are clickable to view record details
    list_display_links = ('id', 'name')

    # Filters in the sidebar
    list_filter = ('status', 'user', 'date_uploaded')

    # Search bar for specific fields
    search_fields = ('name', 'user__username')  # 'user__username' accesses related User's username

    # Default ordering (most recent uploads first)
    ordering = ('-date_uploaded',)

    # Add pagination (optional, Django provides it by default with 100 per page)
    list_per_page = 50  # Adjust the number of items per page
