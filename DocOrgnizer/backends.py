from django.contrib.auth.backends import ModelBackend
from .models import UserProfile

class CustomModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if '@' in username:
            user = UserProfile.objects.filter(email__iexact=username).first()
        else:
            user = UserProfile.objects.filter(full_name__iexact=username).first()

        if user and user.check_password(password):
            return user

        return None
