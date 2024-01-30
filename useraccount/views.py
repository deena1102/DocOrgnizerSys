from django.shortcuts import render , redirect ,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from DocOrgnizer.models import UserProfile
from DocOrgnizer.views import activateEmail
from datetime import datetime
from django.contrib.auth import logout
from django.core.mail import send_mail
from .forms import ContactUsForm , PasswordForm , CustomPasswordChangeForm,CustomEmailChangeForm ,CategoryCreationForm,UpdateCategoryForm
from DocOrgnizerMaria.settings import EMAIL_HOST_USER
from django.http import HttpResponse, FileResponse
from django.utils.encoding import smart_str
from .models import CustomCategory ,Category
from django.core.exceptions import SuspiciousFileOperation
from django.contrib.auth.models import Group
from Crypto.Cipher import AES
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage
from DocOrgnizer.tokens import account_activation_token
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import hmac
import hashlib
from django.conf import settings
from DocOrgnizer.views import  encrypt_national_id
import os
import csv

key = settings.ENCRYPTION_KEY
def generate_key_and_iv(password, salt, key_length, iv_length):
    key_and_iv = PBKDF2(password, salt, dkLen=key_length + iv_length, count=1000, prf=lambda p, s: hmac.new(p, s, hashlib.sha256).digest())
    return key_and_iv[:key_length], key_and_iv[key_length:]

def encrypt_pdf(input_path, output_path, password):
    salt = get_random_bytes(16)
    key, iv = generate_key_and_iv(password.encode('utf-8'), salt, 32, 16)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(input_path, 'rb') as file_in, open(output_path, 'wb') as file_out:
        file_out.write(salt)

        while True:
            chunk = file_in.read(1024 * 1024)  # 1MB chunks
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk = pad(chunk, 16)
            file_out.write(cipher.encrypt(chunk))
        
def decrypt_pdf(input_path, password):
    with open(input_path, 'rb') as file_in:
        salt = file_in.read(16)
        key, iv = generate_key_and_iv(password.encode('utf-8'), salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_content = b''
        while True:
            chunk = file_in.read(1024 * 1024)  # 1MB chunks
            if len(chunk) == 0:
                break
            decrypted_chunk = unpad(cipher.decrypt(chunk), 16)
            decrypted_content += decrypted_chunk

    return decrypted_content

@login_required
def user_profile(request):
        logged_in_user = request.user
        user_profile = UserProfile.objects.get(full_name=logged_in_user)
        is_staff_member = user_profile.is_staff
        belongs_to_group2 = logged_in_user.groups.filter(name='Group2').exists()
        with open('civilregistry.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                data = line.strip().split(',')
                full_name, national_id, birthdate_str = data[:3]
                if full_name == user_profile.full_name:
                    birthdate = datetime.strptime(birthdate_str, '%m/%d/%Y')
                    user_profile.national_id = national_id
                    user_profile.save()
                    context = {
                        'user_profile': user_profile,
                        'birthdate': birthdate,
                        'is_staff_member': is_staff_member
                    }   

        return render(request, 'user/profile.html', context)


@login_required
def change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Password Chang successfully. You can now log in with your new password.")
            return redirect('login')
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'user/update-password.html', {'form': form})

import uuid

def change_email(request):
    new_email = None
    if request.method == 'POST':
        form = CustomEmailChangeForm(request.user, request.POST)
        if form.is_valid():
            new_email = form.cleaned_data['new_email']
            change_email_request(request, request.user, new_email)
            return redirect(reverse('login'))
    else:
        form = CustomEmailChangeForm(user=request.user)
    
    return render(request, 'user/update-email.html', {'form': form, 'new_email': new_email})

from django.core.cache import cache

def change_email_request(request, user, new_email):
    # Generate a unique token for email confirmation
    confirmation_token = str(uuid.uuid4())

    # Save the new_email and confirmation_token in the cache with unique keys
    cache_key_email = f'new_email_{user.pk}'
    cache.set(cache_key_email, new_email, timeout=60 * 15)  # Set expiration time (e.g., 15 minutes)

    cache_key_token = f'email_confirmation_token_{user.pk}'
    cache.set(cache_key_token, confirmation_token, timeout=60 * 15)  # Set expiration time (e.g., 15 minutes)

    # Send an email with a link containing the token
    mail_subject = 'Change User Email Confirmation'
    message = render_to_string('email_change.html', {
        'user': user.full_name,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': confirmation_token,
        'new_email': new_email,
        'protocol': 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[user.email])

    try:
        if email.send():
            messages.success(request, f'Dear <b>{user}</b>, please check your email {user.email}  inbox for a confirmation link to complete the email change process.')
        else:
            messages.error(request, f'Problem sending confirmation email to {user.email}, check if you typed it correctly.')
    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')

from django.core.cache import cache

def confirm_email_change(request, uidb64, token):
    try:            
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = UserProfile.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, UserProfile.DoesNotExist):
        user = None

    if user is not None:
        # Retrieve the confirmation token from the cache
        cache_key_token = f'email_confirmation_token_{user.pk}'
        confirmation_token = cache.get(cache_key_token)

        if confirmation_token == token:
            # Valid confirmation token, change the email
            cache_key_email = f'new_email_{user.pk}'
            new_email = cache.get(cache_key_email)  # Retrieve the new_email from cache

            if new_email:
                user.email = new_email
                user.save()
                messages.success(request, f'Dear <b>{user}</b>, your email has been successfully changed to {user.email}.')
                return redirect('login')
            else:
                messages.error(request, 'New email not provided. Please contact support.')
        else:
            messages.error(request, 'Confirmation link is invalid or has expired. Please check your email or contact support.')
    else:
        messages.error(request, 'Invalid user. Please check your email or contact support.')

    return redirect('login')


@login_required
def user_info(request):
    current_user = request.user
    belongs_to_group1 = current_user.groups.filter(name='Group1').exists()
    logged_in_user = request.user
    user_info = UserProfile.objects.get(full_name=logged_in_user)

    # Initialize variables to store found data
    found_data = None

    with open('civilregistry.txt', 'r') as file:
        reader = csv.reader(file)
        for line in reader:
            try:
                full_name, national_id, birthdate_str, *names, nationality, gender, city = line
            except ValueError:
                print(f"Error unpacking values in line: {line}")
                continue
            if full_name == user_info.full_name:
                # Update user_info here
                user_info.full_name = full_name
                user_info.national_id = national_id
                birthdate = datetime.strptime(birthdate_str, '%m/%d/%Y')
                father_name, grandfather_name, family_name, mother_name = map(str.strip, names)
                
                # Save the found data in the variables
                found_data = {
                    'birthdate': birthdate,
                    'father_name': father_name,
                    'grandfather_name': grandfather_name,
                    'family_name': family_name,
                    'mother_name': mother_name,
                    'nationality': nationality,
                    'gender': gender,
                    'City': city,
                }

                # Save changes to user_info
                user_info.save()

    # Render the template after the loop
    if found_data:
        context = {'user_info': user_info, 'belongs_to_group1': belongs_to_group1, **found_data}
        return render(request, 'user/userinfo.html', context)

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


@login_required
def system_categories(request):
    current_user = request.user
    belongs_to_group1 = current_user.groups.filter(name='Group1').exists()
    return render(request,"user/systemcategories.html",{'belongs_to_group1': belongs_to_group1})

@login_required
def user_categories(request):
    return render(request,"user/usercategories.html")

@login_required
def FAQ(request):
    return render(request,"user/faq.html")

@login_required
def contactus(request):
    if request.method == 'POST':
        form = ContactUsForm(request.POST, request=request)
        if form.is_valid():
            form.save()
            subject = 'New Contact Us Form Submission'
            message = f'Name: {form.cleaned_data["name"]}\nEmail: {form.cleaned_data["email"]}\nMessage: {form.cleaned_data["message"]}'
            from_email = form.cleaned_data["email"]  
            recipient_list = [EMAIL_HOST_USER]  
            send_mail(subject, message, from_email, recipient_list)
            messages.success(request, "Thank you for contacting us! We will get back to you soon.")
            return redirect('contactus')
    else:
        form = ContactUsForm()

    return render(request, "user/contactus.html", {'form': form})

@login_required
def about_us(request):
    return render(request, 'user/aboutus.html')


@login_required
def protectedcategory(request, category_name):
    authenticated = False
    category = get_object_or_404(Category, category_name=category_name)
    form = PasswordForm(user=request.user, data=request.POST)

    if request.method == 'POST':
        if form.is_valid():
            authenticated = True
            return redirect('document', category_name=category_name)
    else:
        form = PasswordForm(user=request.user)

    return render(request, 'user/protected_category.html', {'form': form, 'authenticated': authenticated, 'category_name': category_name})

@login_required
def document(request,category_name):
    category = get_object_or_404(Category, category_name=category_name)
    user_national_id = str(request.user.national_id).strip()
    file_name = f"{category_name}.txt"
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(BASE_DIR,'SystemDoc', file_name)
    pdf_info_list = []
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                national_id, found_pdf_path = line.strip().split(',')
                if national_id.strip() == user_national_id:
                    pdf_info_list.append({
                        'pdf_path': found_pdf_path.strip(),
                        'pdf_name': os.path.basename(found_pdf_path.strip()).lower()  
                    })

    except FileNotFoundError:
        error_message = f"The document file for the category {category_name} does not exist."
        return render(request, 'user/systemcategories.html', {'error_message': error_message, 'category':category})

    return render(request, 'user/DocPage.html', {'pdf_info_list': pdf_info_list, 'category': category, 'user_national_id':user_national_id})

@login_required
def open_pdf(request, category_name, pdf_name):
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf_path = os.path.join(BASE_DIR,"SystemDoc", f"{category_name}.txt")

    try:
        with open(pdf_path, 'r') as file:
            lines = file.readlines()

            for line in lines:
                national_id, found_pdf_path = line.strip().split(',')
                if national_id.strip() == str(request.user.national_id).strip() and pdf_name.lower() == os.path.basename(found_pdf_path.strip()).lower():
                    if os.path.isfile(found_pdf_path.strip()):
                        response = FileResponse(open(found_pdf_path.strip(), 'rb'), content_type='application/pdf')
                        return response

    except FileNotFoundError:
       error_message = f"The document file for the category {category_name} does not exist."
       return render(request, 'user/DocPage.html', {'error_message': error_message})

    return HttpResponse("Invalid PDF request", status=400)

@login_required
def download_pdf(request, category_name, pdf_name):
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf_path = os.path.join(BASE_DIR,"SystemDoc", f"{category_name}.txt")

    try:
        with open(pdf_path, 'r') as file:
            lines = file.readlines()

            for line in lines:
                national_id, found_pdf_path = line.strip().split(',')
                if (
                    national_id.strip() == str(request.user.national_id).strip() and
                    pdf_name.lower() == os.path.basename(found_pdf_path.strip()).lower()
                ):
                    if os.path.isfile(found_pdf_path.strip()):
                        response = FileResponse(open(found_pdf_path.strip(), 'rb'), content_type='application/pdf')
                        response['Content-Disposition'] = f'attachment; filename="{smart_str(pdf_name)}"'
                        return response
    except FileNotFoundError:
        pass  

    return HttpResponse("Invalid PDF request", status=400)


@login_required
def create_category(request):
    user = request.user
    if request.method == 'POST':
        form = CategoryCreationForm(request.POST, request.FILES, user=user)
        if form.is_valid():
            category = form.save(commit=False)
            category.user_profile = user

            if user.categories.count() >= 4:
                form.add_error(None, 'A user can have at most 4 categories.')
                return render(request, 'user/createcategory.html', {'form': form})
            national_id = str(user.national_id).zfill(9)           
            encrypted_national_id = encrypt_national_id(national_id,key)
            BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            user_folder = os.path.join(BASE_DIR,'UserDoc', encrypted_national_id.decode())
            document_name = form.cleaned_data['document_pdf'].name
            document_path = os.path.join(user_folder, document_name)
            # Save the PDF file to the user's folder
            with open(document_path, 'wb+') as destination:
                for chunk in category.document_pdf.chunks():
                    destination.write(chunk)

            output_encrypted_pdf_path = os.path.join(user_folder, f"{os.path.splitext(document_name)[0]}_encrypted.pdf")
            encrypt_pdf(document_path, output_encrypted_pdf_path, user.password)

            os.remove(document_path)

            category.document_pdf = os.path.basename(output_encrypted_pdf_path)
            category.save()

            return redirect('usercategories')  
    else:
        form = CategoryCreationForm(user=user)

    return render(request, 'user/createcategory.html', {'form': form})

@login_required
def User_protectedcategory(request, category_name):
    authenticated = False 
    categories = CustomCategory.objects.filter(category_name=category_name)
    form = PasswordForm(user=request.user, data=request.POST)
    if request.method == 'POST':
        if form.is_valid():
            authenticated = True  
            return redirect('userdocuments', category_name=category_name)
    else:
        form = PasswordForm(user=request.user)
    return render(request, 'user/protected_category.html', {'form': form, 'authenticated': authenticated, 'category_name': category_name})

@login_required
def user_documents(request, category_name):
    user = request.user
    try:
        custom_category = get_object_or_404(CustomCategory, category_name=category_name, user_profile=user)
        pdf_name = os.path.basename(str(custom_category.document_pdf)) 
        national_id = str(user.national_id).zfill(9)           
        encrypted_national_id = encrypt_national_id(national_id,key)
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_folder = os.path.join(BASE_DIR,'UserDoc', encrypted_national_id.decode())
        pdf_path = os.path.join(user_folder, pdf_name)
        if os.path.exists(pdf_path):
            decrypted_pdf_path = pdf_path.replace('.pdf', '_decrypted.pdf')
            return render(request, 'user/user_documents.html', {'pdf_path': decrypted_pdf_path, 'pdf_name': pdf_name, 'category_name': category_name})
        else:
            error_message = f"The PDF file for the category {category_name} does not exist in the user's folder."
            return render(request, 'user/usercategories.html', {'error_message': error_message})
    
    except CustomCategory.DoesNotExist:
        error_message = f"The category {category_name} does not exist for the current user."
        return render(request, 'user/usercategories.html', {'error_message': error_message})
    

@login_required
def useropen_document(request, category_name,pdf_name):
    user = request.user
    try:
        custom_category = get_object_or_404(CustomCategory, category_name=category_name, user_profile=user)
        pdf_name = os.path.basename(str(custom_category.document_pdf))  # Extract the base name of the PDF file
        national_id = str(user.national_id).zfill(9)           
        encrypted_national_id = encrypt_national_id(national_id,key)
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_folder = os.path.join(BASE_DIR,'UserDoc', encrypted_national_id.decode())
        pdf_path = os.path.join(user_folder, pdf_name)
        if os.path.exists(pdf_path):
            decrypted_content = decrypt_pdf(pdf_path, user.password)
            response = HttpResponse(decrypted_content, content_type='application/pdf')
            response['Content-Disposition'] = f'inline; filename="{pdf_name}"'
            return response

        else:
            error_message = f"The PDF file for the category {category_name} does not exist in the user's folder."
            return render(request, 'user/usercategories.html', {'error_message': error_message})

    except CustomCategory.DoesNotExist:
        error_message = f"The category {category_name} does not exist for the current user."
        return render(request, 'user/usercategories.html', {'error_message': error_message})
    

@login_required
def userdownload_document(request, category_name, pdf_name):
    user = request.user
    try:
        custom_category = get_object_or_404(CustomCategory, category_name=category_name, user_profile=user)
        pdf_name = os.path.basename(str(custom_category.document_pdf))  # Extract the base name of the PDF file
        national_id = str(user.national_id).zfill(9)           
        encrypted_national_id = encrypt_national_id(national_id,key)
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        user_folder = os.path.join(BASE_DIR,'UserDoc', encrypted_national_id.decode())
        pdf_path = os.path.join(user_folder, pdf_name)

        # Check if the user is authorized to download the file
        if custom_category.user_profile == user:
            decrypted_content = decrypt_pdf(pdf_path, user.password)
            response = HttpResponse(decrypted_content, content_type='application/pdf')
            decrypted_pdf_path = pdf_path.replace('_encrypted', '')
            with open(decrypted_pdf_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_content)

            response = FileResponse(open(decrypted_pdf_path, 'rb'), content_type='application/pdf')                    
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(decrypted_pdf_path)}"'       
            return response
        else:
            error_message = "You are not authorized to download this file."
            return render(request, 'user/usercategories.html', {'error_message': error_message})
    except CustomCategory.DoesNotExist:
        error_message = f"The category {category_name} does not exist for the current user."
        return render(request, 'user/usercategories.html', {'error_message': error_message})

@login_required
def update_category(request, category_name):
    user = request.user
    category_name = category_name  # Make sure to slugify the category name
    category = get_object_or_404(CustomCategory, category_name=category_name, user_profile=user)
    if request.method == 'POST':
        form = UpdateCategoryForm(request.POST, request.FILES, user=user, instance=category)
        if form.is_valid():
            # Update the category with the new data
            category = form.save(commit=False)
            category.user_profile = user

            if 'document_pdf' in request.FILES:
                national_id = str(user.national_id).zfill(9)           
                # Encrypt the user folder name
                encrypted_national_id = encrypt_national_id(national_id,key)
                BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                user_folder = os.path.join(BASE_DIR,'UserDoc', encrypted_national_id.decode())
                document_name = request.FILES['document_pdf'].name
                document_path = os.path.join(user_folder, document_name)
                
                try:
                    with open(document_path, 'wb+') as destination:
                        for chunk in request.FILES['document_pdf'].chunks():
                                destination.write(chunk)
                    output_encrypted_pdf_path = os.path.join(user_folder, f"{os.path.splitext(document_name)[0]}_encrypted.pdf")
                    encrypt_pdf(document_path, output_encrypted_pdf_path, user.password)
                    os.remove(document_path)
                    category.document_pdf = os.path.basename(output_encrypted_pdf_path)
                except SuspiciousFileOperation:
                    raise SuspiciousFileOperation("Attempted to write outside the storage location.")

            category.save()
            return render(request, 'user/usercategories.html')
        else:
            messages.error(request, 'Error updating the category. Please correct the errors below.')
    else:
        form = UpdateCategoryForm(user=user, instance=category)
    return render(request, 'user/updatecategory.html', {'form': form, 'category': category})

@login_required
def user_management_view(request):
    if request.user.is_superuser:
        all_users = UserProfile.objects.exclude(id=request.user.id)
    elif request.user.is_staff:
        all_users = UserProfile.objects.filter(is_staff=False, is_superuser=False)
    else:
        all_users = UserProfile.objects.exclude(id=request.user.id)

    for user in all_users:
        user.group = 'Group1' if user.groups.filter(name='Group1').exists() else 'Group2'
        user.is_staff = user.is_staff

    is_superuser = request.user.is_superuser

    context = {
        'all_users': all_users,
        'is_superuser': is_superuser,
    }

    return context

@login_required
def update_users_view(request):
    if request.method == 'POST':
        selected_users = request.POST.getlist('selected_users')

        try:
            for national_id in selected_users:
                user = UserProfile.objects.get(national_id=national_id)
                group_key = f'group_{national_id}'
                group = request.POST.get(group_key, None)

                is_staff_key = f'is_staff_{national_id}'
                is_staff = request.POST.get(is_staff_key, '0') == '1'
                existing_groups = user.groups.all()

                if existing_groups.exists():
                    existing_group = existing_groups[0]
                    if group and existing_group.name != group:
                        user.groups.remove(existing_group)
                if group:
                    target_group_name = 'Group1' if group == 'group1' else 'Group2'
                    user.groups.add(Group.objects.get(name=target_group_name))
                user.is_staff = is_staff
                user.save()
            messages.success(request, 'User information updated successfully.')
            return redirect('updateusersview')
        except UserProfile.DoesNotExist:
            messages.error(request, 'User not found.')
        except Exception as e:
            messages.error(request, f'An error occurred: {e}')
    user_management_data = user_management_view(request)
    return render(request, 'user/usersmanagement.html', {'all_users': user_management_data['all_users'], 'is_superuser': user_management_data['is_superuser']})