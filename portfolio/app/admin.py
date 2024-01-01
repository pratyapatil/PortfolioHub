from django.contrib import admin
from app.models import ServiceManagementModel,Portfolio_Management_model,Category_management_model,Blog_Management_model,Brand_management_model,static_content,FAQ,Myuser,OldPassword_Model
# Register your models here.

admin.site.register([ServiceManagementModel,
                        Portfolio_Management_model,
                        Category_management_model,
                        Blog_Management_model,
                        Brand_management_model,
                        static_content,FAQ,Myuser,
                        OldPassword_Model])