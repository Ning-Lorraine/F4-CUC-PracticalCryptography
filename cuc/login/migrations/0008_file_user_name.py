# Generated by Django 4.0.6 on 2022-07-29 17:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0007_remove_file_enckey'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='user_name',
            field=models.CharField(default='', max_length=128),
        ),
    ]