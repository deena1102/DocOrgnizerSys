from django.urls import path,include
from DocOrgnizer.views import  sign_up , home_view, about_us ,activate  , forgot_password, reset_password,login_view, contactus, faq,unlock_account

urlpatterns = [
    # urls.py
    path('', home_view, name='home'),
    path('faq/',faq,name='faq'),
    path('aboutus/', about_us, name='aboutus'),
    path('contact/', contactus, name='contact'),
    path('login/', login_view, name='login'), 
    path('signup/',sign_up,name='signup'),
    path('activate/<uidb64>/<token>', activate, name='activate'),
    path('unlock/<uidb64>/<token>', unlock_account, name='unlock_account'),
    path('forgoturpassword/', forgot_password, name='forgoturpassword'),
    path('reseturpassword/<uidb64>/<token>', reset_password, name='reseturpassword'),
] 

