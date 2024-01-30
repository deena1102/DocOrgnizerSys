from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from DocOrgnizer.models import ContactUs
import os
from .models import CustomCategory, Category

class CustomPasswordChangeForm(PasswordChangeForm):
    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        user = self.user
        if not user.check_password(old_password):
            raise ValidationError('Incorrect old password.')
        return old_password

    def clean_new_password1(self):
        new_password1 = self.cleaned_data.get('new_password1')
        confirm_password2 = self.cleaned_data.get('confirm_password2')

        if self.cleaned_data.get('old_password') == new_password1:
            raise ValidationError('New password must be different from the old password.')

        return new_password1

    def clean_confirm_password2(self):
        new_password1 = self.cleaned_data.get('new_password1')
        confirm_password2 = self.cleaned_data.get('confirm_password2')

        # Check if the new password matches the confirmation password
        if confirm_password2 and new_password1 and confirm_password2 != new_password1:
            raise ValidationError('Passwords do not match.', code='password_mismatch')

        return confirm_password2

User = get_user_model()
class CustomEmailChangeForm(forms.Form):
    current_email = forms.EmailField(label="Current Email Address", widget=forms.EmailInput(attrs={'class': 'input is-medium'}))
    new_email = forms.EmailField(label="New Email Address", widget=forms.EmailInput(attrs={'class': 'input is-medium'}))
    password = forms.CharField(label="Password", widget=forms.PasswordInput(attrs={'class': 'input is-medium'}))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(CustomEmailChangeForm, self).__init__(*args, **kwargs)
        

    def clean_current_email(self):
        current_email = self.cleaned_data.get('current_email')
        user = self.user
        if user.email != current_email:
            raise ValidationError('Incorrect current email address.')
        return current_email

    def clean_new_email(self):
        new_email = self.cleaned_data.get('new_email')
        user = self.user

        if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
            raise ValidationError('This email address is already in use.')
        if new_email.lower() == self.user.email.lower():
            raise ValidationError('New email cannot be similar to the current email.')
        return new_email

    def clean_password(self):
        password = self.cleaned_data.get('password')
        user = self.user
        if not user.check_password(password):
            raise ValidationError('Incorrect password.')
        return password
    


class ContactUsForm(forms.ModelForm):
    class Meta:
        model = ContactUs
        fields = ['name', 'email', 'message']
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
    
    def clean(self):
        cleaned_data = super().clean()
        name = cleaned_data.get('name')
        email = cleaned_data.get('email')
        user = self.request.user if hasattr(self, 'request') and self.request.user.is_authenticated else None
        if name != user.full_name or email != user.email:
            self.add_error(None, "The provided name and email do not match the currently logged-in user.")
        return cleaned_data
    

class PasswordForm(forms.Form):
    password = forms.CharField(label="Password", widget=forms.PasswordInput(attrs={'class': 'input is-medium'}))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get('password')
        user = self.user

        if user is not None and not user.check_password(password):
            raise ValidationError('Incorrect password.')

        return password


class CategoryCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = CustomCategory
        fields = ['category_name', 'category_description', 'document_pdf']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(CategoryCreationForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')

        if not self.user.check_password(password):
            raise ValidationError('Incorrect password.')

    def clean_category_name(self):
        category_name = self.cleaned_data.get('category_name')
        category_name_lower = category_name.lower()  # Convert to lowercase for case-insensitive comparison

        existing_custom_category = CustomCategory.objects.filter(category_name__iexact=category_name_lower, user_profile=self.user)
        if existing_custom_category.exists():
            raise ValidationError('You already have a category with this name.')

        existing_category = Category.objects.filter(category_name__iexact=category_name_lower)
        if existing_category.exists():
            raise ValidationError('Category name is already used in the system categories.')

        return category_name

    def clean_document_pdf(self):
        value = self.cleaned_data.get('document_pdf')
        limit_mb = 10
        if value.size > limit_mb * 1024 * 1024:
            raise ValidationError('File size must be no more than {} MB'.format(limit_mb))

        user_custom_categories = CustomCategory.objects.filter(user_profile=self.user).exclude(pk=self.instance.pk)
        def add_encrypted_suffix(file_name):
            base_name, extension = os.path.splitext(file_name)
            return f"{base_name}_encrypted{extension}"
            
        value_with_encrypted_suffix = add_encrypted_suffix(os.path.basename(value.name))            
        existing_documents = [category for category in user_custom_categories if
                                  os.path.basename(category.document_pdf.name) == value_with_encrypted_suffix]

        if existing_documents:
            raise ValidationError('You already have a category with this document.')

        return value


class UpdateCategoryForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)

    class Meta:
        model = CustomCategory
        fields = ['category_name', 'category_description', 'document_pdf']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.instance = kwargs.get('instance', None)
        super(UpdateCategoryForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')

        if password and not self.user.check_password(password):
            raise ValidationError('Incorrect password.')

        if 'category_name' in cleaned_data and cleaned_data['category_name'] != self.instance.category_name:
            self.clean_category_name()
        if 'document_pdf' in cleaned_data and cleaned_data['document_pdf'] != self.instance.document_pdf:
            self.clean_document_pdf()

        return cleaned_data

    def clean_category_name(self):
        category_name = self.cleaned_data.get('category_name')
        category_name_lower = category_name.lower()  # Convert to lowercase for case-insensitive comparison

        existing_custom_category = CustomCategory.objects.filter(
            category_name__iexact=category_name_lower, user_profile=self.user
        ).exclude(pk=self.instance.pk)
        
        if existing_custom_category.exists():
            raise ValidationError('You already have a category with this name.')

        existing_category = Category.objects.filter(category_name__iexact=category_name_lower)
        if existing_category.exists():
            raise ValidationError('Category name is already used in the system categories.')

        return category_name

    def clean_document_pdf(self):
        value = self.cleaned_data.get('document_pdf')

        if value:
            user_custom_categories = CustomCategory.objects.filter(user_profile=self.user).exclude(pk=self.instance.pk)

            def add_encrypted_suffix(file_name):
                base_name, extension = os.path.splitext(file_name)
                return f"{base_name}_encrypted{extension}"

            value_with_encrypted_suffix = add_encrypted_suffix(os.path.basename(value.name))
            
            existing_documents = [category for category in user_custom_categories if
                                  os.path.basename(category.document_pdf.name) == value_with_encrypted_suffix]
            if existing_documents:
                raise ValidationError('You already have a category with this document.')
            return value


