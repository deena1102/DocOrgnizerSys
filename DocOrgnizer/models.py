from cgi import FieldStorage
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db import models


class UserProfile(AbstractUser):
    full_name = models.CharField(max_length=255, unique=True)
    national_id = models.PositiveIntegerField(unique=True)
    email = models.EmailField(unique=True)

    username=None
    first_name = None
    last_name = None
    USERNAME_FIELD = 'full_name'
    REQUIRED_FIELDS = ['email']

    def _str_(self):
        return self.full_name

class ContactUs(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class LoginAttempt(models.Model):
    user_id = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)
