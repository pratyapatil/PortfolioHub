# Generated by Django 5.0 on 2023-12-29 18:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_oldpassword_model'),
    ]

    operations = [
        migrations.AlterField(
            model_name='myuser',
            name='is_active',
            field=models.BooleanField(default=False),
        ),
    ]
