from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings 

# Custom User Model
class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=30, blank=False, null=False)
    last_name = models.CharField(max_length=30, blank=False, null=False)
    is_super_admin = models.BooleanField(default=False)
    country = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return self.username

# UploadedFile Model
class UploadedFile(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Use CustomUser here
        on_delete=models.CASCADE,
        related_name="uploaded_files"
    )
    name = models.CharField(max_length=255)
    size = models.CharField(max_length=50)
    total_cost = models.IntegerField(default=0)
    YES_NO_CHOICES = [
        ('Yes', 'Yes'),
        ('No', 'No'),
    ]
    verbatim = models.CharField(max_length=3, choices=YES_NO_CHOICES, default='No')
    rush_order= models.CharField(max_length=3, choices=YES_NO_CHOICES, default='No')
    timestamp = models.CharField(max_length=3, choices=YES_NO_CHOICES, default='Yes')
    
    SPELLING_CHOICES = [
        ('US', 'US'),
        ('British', 'British'),
        ('Australia', 'Australia'),
        ('Canada', 'Canada'),
    ]
    spelling = models.CharField(max_length=10, choices=SPELLING_CHOICES, default="US")
    additional_info = models.TextField(null=True, blank=True)
    file = models.FileField(upload_to="files/", null=True, blank=True)
    date_uploaded = models.DateTimeField(auto_now_add=True)

    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Processing', 'Processing'),
        ('Completed', 'Completed'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')

    def __str__(self):
        return self.name

# Notification Model
class Notification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="notifications")
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:30]}"
