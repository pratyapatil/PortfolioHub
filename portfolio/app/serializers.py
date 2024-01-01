from rest_framework import serializers
from app.models import Myuser,static_content,FAQ,ServiceManagementModel, Category_management_model, Portfolio_Management_model, Blog_Management_model, Brand_management_model
API_BASE_URL = 'http://172.16.12.253:9090'


class MyuserSerializerEdit(serializers.ModelSerializer):
    Images = serializers.SerializerMethodField()
    class Meta:
        model = Myuser
        fields = ['id', 'email', 'Images', 'full_name']
    def get_Images(self, obj):
        if obj.Images:
            return f'{API_BASE_URL}{obj.Images.url}'
        return None

class MyuserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Myuser
        fields = ['id', 'email', 'Images', 'full_name']


class Static_ContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = static_content
        fields = '__all__'

class FAQSerializer(serializers.ModelSerializer):
    class Meta:
        model = FAQ
        fields = '__all__'

class ServiceManagementModel_serializer(serializers.ModelSerializer):
    formatted_created_datetime = serializers.SerializerMethodField()
    Service_Image = serializers.SerializerMethodField()
    class Meta:
        model = ServiceManagementModel
        exclude= ['Created_Date_Time']
    def get_Service_Image(self, obj):
        if obj.Service_Image:
            return f'{API_BASE_URL}{obj.Service_Image.url}'
        return None
    def get_formatted_created_datetime(self, obj):
        if obj.Created_Date_Time:
            date = obj.Created_Date_Time.strftime("%Y-%m-%d")
            time =obj.Created_Date_Time.strftime("%H:%M")
            return f'{date} {time}'
        return None

class ServiceManagementModel_serializer2(serializers.ModelSerializer):
    class Meta:
        model = ServiceManagementModel
        fields = '__all__'

class Category_management_model_serializer(serializers.ModelSerializer):
    formatted_created_datetime = serializers.SerializerMethodField()
    class Meta:
        model = Category_management_model
        exclude= ['Created_Date_Time']

    def get_formatted_created_datetime(self, obj):
        if obj.Created_Date_Time:
            date = obj.Created_Date_Time.strftime("%Y-%m-%d")
            time =obj.Created_Date_Time.strftime("%H:%M")
            return f'{date} {time}'
        return None

class Category_management_model_serializer1(serializers.ModelSerializer):
    class Meta:
        model = Category_management_model
        fields = '__all__'
class Portfolio_Management_model_serializer(serializers.ModelSerializer):
    formatted_created_datetime = serializers.SerializerMethodField()
    Portfolio_Image = serializers.SerializerMethodField()
    Portfolio_Category = Category_management_model_serializer()
    class Meta:
        model = Portfolio_Management_model
        exclude= ['Created_Date_Time']
    def get_Portfolio_Image(self, obj):
        if obj.Portfolio_Image:
            return f'{API_BASE_URL}{obj.Portfolio_Image.url}'
        return None
    def get_formatted_created_datetime(self, obj):
        if obj.Created_Date_Time:
            date = obj.Created_Date_Time.strftime("%Y-%m-%d")
            time =obj.Created_Date_Time.strftime("%H:%M")
            return f'{date} {time}'
        return None

class Portfolio_Management_model_serializer2(serializers.ModelSerializer):
    class Meta:
        model = Portfolio_Management_model
        fields = '__all__'

class Blog_Management_model_serializer(serializers.ModelSerializer):
    formatted_created_datetime = serializers.SerializerMethodField()
    Blog_Image = serializers.SerializerMethodField()
    Blog_Category = Category_management_model_serializer()

    class Meta:
        model = Blog_Management_model
        exclude= ['Created_Date_Time']

    def get_Blog_Image(self, obj):
        if obj.Blog_Image:
            return f'{API_BASE_URL}{obj.Blog_Image.url}'
        return None
    def get_formatted_created_datetime(self, obj):
        if obj.Created_Date_Time:
            date = obj.Created_Date_Time.strftime("%Y-%m-%d")
            time =obj.Created_Date_Time.strftime("%H:%M")
            return f'{date} {time}'
        return None

class Blog_Management_model_serializer1(serializers.ModelSerializer):
    class Meta:
        model = Blog_Management_model
        fields = '__all__'

class Brand_management_model_serializer(serializers.ModelSerializer):
    formatted_created_datetime = serializers.SerializerMethodField()
    brand_Image = serializers.SerializerMethodField()
    class Meta:
        model = Brand_management_model
        exclude= ['Created_Date_Time']
    def get_brand_Image(self, obj):
        if obj.brand_Image:
            return f'{API_BASE_URL}{obj.brand_Image.url}'
        return None
    def get_formatted_created_datetime(self, obj):
        if obj.Created_Date_Time:
            date = obj.Created_Date_Time.strftime("%Y-%m-%d")
            time =obj.Created_Date_Time.strftime("%H:%M")
            return f'{date} {time}'
        return None

class Brand_management_model_serializer2(serializers.ModelSerializer):
    class Meta:
        model = Brand_management_model
        fields = '__all__'
