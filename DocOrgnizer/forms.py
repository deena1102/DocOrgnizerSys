import os
from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from PIL import Image
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth import get_user_model
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox
from DocOrgnizer.models import UserProfile, LoginAttempt  
from django.utils.translation import gettext_lazy as _ 
from django.db.models import Q
from django.utils import timezone
from .validators import (
    IsEntireAlphaPasswordValidator,
    HasUpperCasePasswordValidator,
    HasLowerCasePasswordValidator,
    HasNumberPasswordValidator,
    HasSpecialCharacterPasswordValidator,
)

class SignUpForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = UserProfile
        fields = ['full_name', 'national_id', 'email',  'password', 'confirm_password']
    def clean_full_name(self):
        full_name = self.cleaned_data['full_name']
        if not all(char.isalpha() or char.isspace() for char in full_name):
            raise ValidationError('Full name must contain only letters and spaces.')
        return full_name

    def clean_national_id(self):
        national_id = self.cleaned_data['national_id']
        if len(str(national_id)) != 9 or not national_id > 0:
            raise ValidationError('National ID must be a 9-digit positive number.')
        return national_id

    def clean_password(self):
        password = self.cleaned_data.get('password')
        validators = [
            IsEntireAlphaPasswordValidator(),
            HasUpperCasePasswordValidator(),
            HasLowerCasePasswordValidator(),
            HasNumberPasswordValidator(),
            HasSpecialCharacterPasswordValidator(),
        ]

        for validator in validators:
            validator.validate(password)

        return password
    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            # Validate email format
            validate_email(email)
        except ValidationError:
            raise ValidationError('Invalid email address.')

        # Check if the email already exists in the database
        if UserProfile.objects.filter(email=email).exists():
            raise ValidationError('Email is already in use.')
        return email
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        full_name = cleaned_data.get('full_name')
        national_id = cleaned_data.get('national_id')
        if not full_name or not national_id:
        # If earlier validations failed, don't proceed with further checks
            return cleaned_data
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_path = os.path.join(BASE_DIR, 'civilregistry.txt')
        with open(file_path, 'r') as file:
            lines = file.readlines()
            matching_line = None

            for line in lines:
                attributes = line.strip().split(',')
                print(f"User Input: {full_name}, {national_id}")
                print(f"File Data: {attributes[0]}, {attributes[1]}")
                if full_name.lower().strip() == attributes[0].lower().strip() and str(national_id) == attributes[1]:
                    matching_line = line
                    break
            if matching_line is None:
                print("Invalid Credentials. Do not match with civil registry.")
                raise ValidationError("Invalid Credentials. Do not match with civil registry.", code='invalid_credentials')               

        if password and confirm_password and password != confirm_password:
            raise ValidationError('Passwords do not match.', code='password_mismatch')

        return cleaned_data

class ForgotPasswordForm(PasswordResetForm):
    email = forms.EmailField(label='Enter your email to reset password', max_length=254)

    def clean_email(self):
        email = self.cleaned_data['email']
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise forms.ValidationError("This email address is not associated with any account .")

        if not user.is_active:
            raise forms.ValidationError("Account not active or other validation issue.")

        return email
    
class PasswordResetForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean_password(self):
        password = self.cleaned_data.get('password')
        validators = [
            IsEntireAlphaPasswordValidator(),
            HasUpperCasePasswordValidator(),
            HasLowerCasePasswordValidator(),
            HasNumberPasswordValidator(),
            HasSpecialCharacterPasswordValidator(),
        ]

        for validator in validators:
            validator.validate(password)

        return password

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            raise ValidationError('Passwords do not match.', code='password_mismatch')

        return cleaned_data
    
class SignInViaEmailOrUsernameForm(forms.Form):
    email_or_username = forms.CharField(label=_('Email or Username'))
    password = forms.CharField(label=_('Password'), widget=forms.PasswordInput)
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)   
     
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
    def clean(self):
        from .views import accountLockedEmail
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        email_or_username = cleaned_data.get('email_or_username')

        user = UserProfile.objects.filter(Q(full_name__iexact=email_or_username) | Q(email__iexact=email_or_username)).first()
        if not user:
            raise ValidationError(_('You entered an invalid Credentials.'))
        
        if not user.is_active:
            raise ValidationError(_('This account is not active.'))
      
        if not user.check_password(password):
            login_attempt = LoginAttempt.objects.create(user_id=user, timestamp=timezone.now(), successful=False)
            failed_attempts = LoginAttempt.objects.filter(user_id=user, successful=False).count()
            if failed_attempts >= 3:
                user.is_active = False
                user.save()
                accountLockedEmail(self.request, user, user.email)
                LoginAttempt.objects.filter(user_id=user, successful=False).delete()
                raise ValidationError(_('Account locked due to multiple failed login attempts.Please check your email to unlock your account.'))

            raise ValidationError(_('You entered an invalid Credentials.'))
       

        return cleaned_data

    def clean_captcha(self):
         captcha_value = self.cleaned_data.get('captcha', '')
         if not captcha_value:
             raise ValidationError(_('Captcha validation failed. Please try again.'))

    
class ContactUsForm(forms.Form):
    name = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)
    message = forms.CharField(widget=forms.Textarea, required=True)
    created_at = forms.DateTimeField(widget=forms.HiddenInput(), required=False)
    
   


