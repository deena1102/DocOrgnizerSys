from django.urls import path
from .views import user_profile , change_password,change_email,user_info , logout_view, system_categories, user_categories, update_category, contactus, create_category,about_us
from .views import protectedcategory , document,open_pdf ,download_pdf , User_protectedcategory, user_documents , useropen_document,userdownload_document, FAQ
from .views import update_users_view , confirm_email_change


urlpatterns = [
    path('profile/', user_profile, name='profile'),
    path('changepassword/', change_password, name='changepassword'),
    path('changeemail/', change_email, name='changeemail'),
    path('userinfo/', user_info, name='userinfo'),
    path('logout/', logout_view, name='logout'),
    path('systemcategories/', system_categories, name='systemcategories'),
    path('usercategories/', user_categories, name='usercategories'),
    path('createcategory/', create_category, name='createcategory'),
    path('contactus/', contactus, name='contactus'),
    path('aboutus/', about_us, name='about'),
    path('faq/', FAQ, name='FAQ'),
    path('document/<str:category_name>/',document, name='document'),
    path('open_pdf/<str:category_name>/<str:pdf_name>/', open_pdf, name='open_pdf'),
    path('download_pdf/<str:category_name>/<str:pdf_name>/', download_pdf, name='download_pdf'),
    path('useraccount/userprotectedcategory/<str:category_name>/', User_protectedcategory, name='userprotectedcategory'),
    path('protectedcategory/<str:category_name>/', protectedcategory, name='protectedcategory'),
    path('userdocuments/<str:category_name>/', user_documents, name='userdocuments'),
    path('userdocuments/<str:category_name>/<str:pdf_name>/', useropen_document, name='open_document'),
    path('userdocuments/<str:category_name>/<str:pdf_name>/', userdownload_document, name='download_document'),
    path('updatecategory/<str:category_name>/', update_category, name='updatecategory'),
    #path('usersmanagement/', user_management_view, name='usersmanagement'),
    path('confirm-email/<str:uidb64>/<str:token>/', confirm_email_change, name='confirm_email_change'),

    path('updateusers/', update_users_view, name='updateusersview'),

]
