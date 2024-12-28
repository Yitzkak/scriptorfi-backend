from django.db import models
from django.contrib.auth.models import User, AbstractUser

class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="uploaded_files")
    name = models.CharField(max_length=255)
    size = models.CharField(max_length=50)
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


### Superuser
class CustomUser(AbstractUser):
    is_super_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.username