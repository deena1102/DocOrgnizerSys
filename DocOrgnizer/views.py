# views.py
from django.contrib import messages
from django.shortcuts import render, redirect
from DocOrgnizerMaria.settings import EMAIL_HOST_USER
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils import timezone
from django.core.mail import EmailMessage
from .tokens import account_activation_token,reset_password_token ,PasswordResetTokenGenerator
from django.contrib.auth import authenticate, login
from .forms import ForgotPasswordForm, PasswordResetForm ,ContactUsForm ,SignUpForm
from .forms import ContactUsForm ,SignInViaEmailOrUsernameForm
from django.core.mail import send_mail
from django.utils.translation import gettext as _
from .models import ContactUs
from cryptography.hazmat.primitives import padding
import base64
from django.conf import settings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

key = settings.ENCRYPTION_KEY
def encrypt_national_id(national_id, key):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(national_id.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext)

def sign_up(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.is_active = False
            user.save()
            user.groups.add(1)
            activateEmail(request, user, form.cleaned_data.get('email'))
            return redirect(reverse('login')) 
    else:
        form = SignUpForm()

    

    return render(request, 'registreation/signup.html', {'form': form})

def activateEmail(request, user, to_email):
    mail_subject = 'Activate your user account.'
    message = render_to_string('activate_account.html', {
        'user': user.full_name,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
            received activation link to confirm your email. <b>Note:</b> Check your spam.')
    else:
        messages.error(request, f'Problem sending confirmation email to {to_email}, check if you typed it correctly.')

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        if user.is_active:
            messages.error(request, 'Account is already activated. Please try logging in.')
        else:
            user.is_active = True
            user.save()
            national_id = user.national_id  
            national_id = str(national_id)

            create_folder_for_user(user, national_id)
            messages.success(request, f'Dear <b>{user}</b>, Thank you for your email confirmation. Now you can log in to your account.')
    else:
        messages.error(request, 'Activation link is invalid, it can only be used once. Please check your email or contact support.')

    return redirect('login')

def create_folder_for_user(user, national_id):
    national_id = str(user.national_id).zfill(9)
    encrypted_national_id = encrypt_national_id(national_id,key)
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    user_folder = os.path.join(BASE_DIR,'UserDoc', encrypted_national_id.decode())
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    return user_folder

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            User = get_user_model()

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, "This email address is not associated with any account.")
                return render(request, 'registreation/forgoturpassword.html', {'form': form})

            if not user.is_active:
                messages.error(request, "This account is not active.")
                return render(request, 'registreation/forgoturpassword.html', {'form': form})

            send_reset_email(request, user, email)
    else:
        form = ForgotPasswordForm()

    return render(request, 'registreation/forgoturpassword.html', {'form': form})

reset_password_token = PasswordResetTokenGenerator()
def send_reset_email(request, user, to_email):
    if user.is_active:
        mail_subject = 'Reset Your Password.'
        message = render_to_string('reset_password.html', {
            'user': user.full_name,
            'domain': get_current_site(request).domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': reset_password_token.make_token(user),
            'protocol': 'https' if request.is_secure() else 'http'
        })

        email = EmailMessage(mail_subject, message, to=[to_email])
        if email.send():
            messages.success(request,f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
            the received Password Reset link to reset your password. <b>Note:</b> Check your spam folder.')
        else:
            messages.error(request, f'Problem sending confirmation email to {to_email}, check if you typed it correctly.')
            
            
reset_password_token = PasswordResetTokenGenerator()
def reset_password(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and reset_password_token.check_token(user, token):
        if request.method == 'POST':
            form = PasswordResetForm(request.POST)
            if form.is_valid():
                # Set the password using set_password to ensure it's properly hashed
                user.set_password(form.cleaned_data['password'])
                user.save()

                messages.success(request, "Password reset successfully. You can now log in with your new password.")
                return redirect(reverse('login'))  # Redirect to a success page or login page
            else:
                for error in form.non_field_errors():
                    messages.error(request, error)
        else:
            form = PasswordResetForm()

        return render(request, 'registreation/reseturpassword.html', {'form': form, 'reset_error': None})
    else:

        messages.error(request, 'Invalid password reset link. Please request a new one.')

    form = PasswordResetForm()  
    return render(request, 'registreation/login.html', {'form': form, 'reset_error': 'Invalid password reset link. Please request a new one.'})
    
def login_view(request):
    if request.method == 'POST':
        form = SignInViaEmailOrUsernameForm(request.POST,request=request)

        if form.is_valid():
            # Authentication
            host = request.get_host()
            username_or_email = form.cleaned_data['email_or_username']
            password = form.cleaned_data['password']

            # Use the correct field for authentication (email in this case)
            user = authenticate(request, username=username_or_email, password=password)
            if user is not None:
                login(request, user)
                return redirect('systemcategories')  # Redirect to the desired URL after successful login
            else:
                # Authentication failed
                form.add_error(None, _('Invalid login credentials'))
    
    else:
        form = SignInViaEmailOrUsernameForm()

    return render(request, 'registreation/login.html', {'form': form})
   

def home_view(request):
    return render(request, 'home.html')

def contactus(request):
    if request.method == 'POST':
        form = ContactUsForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            message = form.cleaned_data['message']
            created_at = timezone.now()
            # Create a new ContactUs instance and save it to the database
            ContactUs.objects.create(name=name, email=email, message=message, created_at=created_at)
            subject = 'New Contact Us Form Submission'
            message = f'Name: {form.cleaned_data["name"]}\nEmail: {form.cleaned_data["email"]}\nMessage: {form.cleaned_data["message"]}'
            from_email = form.cleaned_data["email"]  # Use the user's email as the sender
            recipient_list = [EMAIL_HOST_USER]  # Send email to EMAIL_HOST
            send_mail(subject, message, from_email, recipient_list)
            messages.success(request, "Thank you for contacting us! We will get back to you soon.")
            return redirect('login')
    else:
        form = ContactUsForm()

    return render(request, 'registreation/contactus.html', {'form': form})

def accountLockedEmail(request, user, to_email):
    mail_subject = 'Unlock Your Account'
    message = render_to_string('unlock_account.html', {
        'user': user.full_name,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    email.send()

def unlock_account(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        if user.is_active:
            messages.error(request, 'Account is already unlocked. Please try logging in.')
        else:
            user.is_active = True
            user.save()
            national_id = user.national_id  
            national_id = str(national_id)

            messages.success(request, f'Dear <b>{user}</b>, Your account has been successfully unlocked. Now you can log in.')
    else:
        messages.error(request, 'Unlock link is invalid, it can only be used once. Please check your email or contact support.')

    return redirect('login')


def about_us(request):
    return render(request, 'registreation/about.html')
def faq(request):
    return render(request,"registreation/FAQ.html")

