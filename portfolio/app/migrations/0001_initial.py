# Generated by Django 5.0 on 2023-12-28 18:49

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Brand_management_model',
            fields=[
                ('sr_no', models.IntegerField(default=True, primary_key=True, serialize=False, unique=True)),
                ('brand_name', models.CharField(max_length=256, null=True)),
                ('brand_Image', models.ImageField(blank=True, null=True, upload_to='media')),
                ('Created_Date_Time', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='Category_management_model',
            fields=[
                ('Category_name', models.CharField(max_length=256, null=True)),
                ('type', models.CharField(max_length=256, null=True)),
                ('sr_no', models.IntegerField(default=True, primary_key=True, serialize=False, unique=True)),
                ('Created_Date_Time', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='FAQ',
            fields=[
                ('sr_no', models.AutoField(primary_key=True, serialize=False)),
                ('question', models.CharField(max_length=255)),
                ('answer', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='ServiceManagementModel',
            fields=[
                ('sr_no', models.IntegerField(default=True, primary_key=True, serialize=False, unique=True)),
                ('Service_Name', models.CharField(max_length=256, null=True)),
                ('Service_ID', models.IntegerField(blank=True, null=True)),
                ('Service_Image', models.ImageField(null=True, upload_to='media')),
                ('Created_Date_Time', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='static_content',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(default='Default Title', max_length=255)),
                ('content', models.TextField(default='Default Content')),
            ],
        ),
        migrations.CreateModel(
            name='Myuser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('full_name', models.CharField(blank=True, default=None, max_length=40, null=True)),
                ('Images', models.ImageField(default='', null=True, upload_to='images/')),
                ('role', models.CharField(choices=[('admin', 'Admin'), ('user', 'User')], default='student', max_length=20)),
                ('password', models.CharField(max_length=16)),
                ('otp', models.IntegerField(blank=True, default=None, null=True)),
                ('is_valid', models.BooleanField(default=False)),
                ('is_block', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('otp_created_at', models.DateTimeField(default=django.utils.timezone.now, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Blog_Management_model',
            fields=[
                ('sr_no', models.IntegerField(default=True, primary_key=True, serialize=False, unique=True)),
                ('Blog_Title', models.CharField(max_length=256, null=True)),
                ('Blog_Image', models.ImageField(blank=True, null=True, upload_to='media')),
                ('Created_Date_Time', models.DateTimeField(default=django.utils.timezone.now)),
                ('Blog_Author', models.CharField(max_length=256, null=True)),
                ('Blog_Description', models.TextField(null=True)),
                ('Blog_Category', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app.category_management_model')),
            ],
        ),
        migrations.CreateModel(
            name='Portfolio_Management_model',
            fields=[
                ('sr_no', models.IntegerField(default=True, primary_key=True, serialize=False, unique=True)),
                ('Portfolio_Name', models.CharField(max_length=256, null=True)),
                ('Portfolio_Image', models.ImageField(blank=True, null=True, upload_to='media')),
                ('Created_Date_Time', models.DateTimeField(default=django.utils.timezone.now)),
                ('Portfolio_Category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.category_management_model')),
            ],
        ),
    ]
