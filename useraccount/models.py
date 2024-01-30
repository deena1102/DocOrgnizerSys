from django.db import models
from DocOrgnizer.models import UserProfile

class Category(models.Model):
    category_id = models.AutoField(primary_key=True)
    category_name = models.CharField(max_length=255)

    def __str__(self):
        return self.category_name

    
class CustomCategory(models.Model):
    category_name = models.CharField(max_length=15)
    category_description = models.CharField(max_length=50)
    document_pdf = models.FileField(upload_to='C:\\UserDoc/')
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='categories')

    def _str_(self):
        return self.category_nam