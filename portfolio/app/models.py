from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser,PermissionsMixin
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password,**extra_fields):
        if not email:
            raise ValueError("Please enter an email address")

        email = self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',False)
        extra_fields.setdefault('is_superuser',False)
        return self._create_user(email,password,**extra_fields)

    def create_superuser(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        return self._create_user(email,password,**extra_fields)

class Myuser(AbstractBaseUser,PermissionsMixin):
    USER_ROLES=(
        ('admin','Admin'),
        ('user','User')

    )

    email=models.EmailField(unique=True)
    name=models.CharField(max_length=255,null=True)
    full_name = models.CharField(max_length=40,blank=True, null=True, default=None)
    Images = models.ImageField(upload_to='images/',default="",null=True)
    role = models.CharField(max_length=20,choices=USER_ROLES, default='student')
    password = models.CharField(max_length=16)
    otp = models.IntegerField(blank=True, null=True, default=None)
    is_valid = models.BooleanField(default=False)
    is_block=models.BooleanField(default=False)
    is_active=models.BooleanField(default=False)
    is_superuser=models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    otp_created_at = models.DateTimeField(default=timezone.now,null=True)
    objects=CustomUserManager()
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]

class OldPassword_Model(models.Model):
    user=models.ForeignKey(Myuser,on_delete=models.CASCADE)
    oldpassword= models.CharField(max_length=16)


class static_content(models.Model):
    title = models.CharField(max_length=255,null=False,default="Default Title")
    content = models.TextField(null=False, default="Default Content")
    def __str__(self):
        return self.title


class FAQ(models.Model):
    sr_no = models.AutoField(primary_key=True)
    question = models.CharField(max_length=255)
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.question
    
class ServiceManagementModel(models.Model):
    sr_no = models.IntegerField(primary_key=True, default=True, unique=True)
    Service_Name = models.CharField(max_length=256, null=True)
    Service_ID = models.IntegerField(null=True, blank=True)
    Service_Image = models.ImageField(upload_to='media', null=True)
    Created_Date_Time = models.DateTimeField(default=timezone.now)
    def __str__(self):
        if self.Service_Name:
            return self.Service_Name
        else:
            return "Unnamed Service"

class Category_management_model(models.Model):
    Category_name = models.CharField(null=True, max_length=256)
    type = models.CharField(null=True, max_length=256)
    sr_no = models.IntegerField(primary_key=True, default=True, unique=True)
    Created_Date_Time = models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.Category_name


class Portfolio_Management_model(models.Model):
    sr_no = models.IntegerField(primary_key=True, default=True, unique=True)
    Portfolio_Category = models.ForeignKey(Category_management_model, on_delete=models.CASCADE)
    Portfolio_Name = models.CharField(max_length=256, null=True)
    Portfolio_Image = models.ImageField(upload_to='media', null=True, blank=True)
    Created_Date_Time = models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.Portfolio_Name


class Blog_Management_model(models.Model):
    sr_no = models.IntegerField(primary_key=True, default=True, unique=True)
    Blog_Title = models.CharField(max_length=256, null=True)
    Blog_Category = models.ForeignKey(Category_management_model, on_delete=models.CASCADE, null=True)
    Blog_Image = models.ImageField(upload_to='media', null=True, blank=True)
    Created_Date_Time = models.DateTimeField(default=timezone.now)
    Blog_Author = models.CharField(max_length=256, null=True)
    Blog_Description = models.TextField(null=True)
    def __str__(self):
        return self.Blog_Title


class Brand_management_model(models.Model):
    sr_no = models.IntegerField(primary_key=True, default=True, unique=True)
    brand_name = models.CharField(max_length=256, null=True)
    brand_Image = models.ImageField(upload_to='media', null=True, blank=True)
    Created_Date_Time = models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.brand_name or "No Brand Name Provided"
