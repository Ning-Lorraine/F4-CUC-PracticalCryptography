# Generated by Django 4.0.6 on 2022-07-20 18:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0004_fileinfo'),
    ]

    operations = [
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=128, unique=True)),
                ('filename', models.FileField(upload_to='upload/%Y%m%d')),
                ('size', models.IntegerField(default=0)),
                ('enckey', models.CharField(default=' ', max_length=2048)),
                ('sha256', models.CharField(default=' ', max_length=256)),
                ('create_time', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Key',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('public_key', models.CharField(max_length=256)),
                ('secret_key', models.CharField(max_length=256)),
            ],
        ),
        migrations.DeleteModel(
            name='FileInfo',
        ),
    ]