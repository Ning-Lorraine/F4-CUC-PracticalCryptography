# Generated by Django 4.0.6 on 2022-08-11 14:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0009_file_keynumber'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='keynumber',
            field=models.CharField(default='', max_length=128),
        ),
    ]
