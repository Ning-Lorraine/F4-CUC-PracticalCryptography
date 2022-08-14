# Generated by Django 4.0.6 on 2022-08-13 02:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0010_alter_file_keynumber'),
    ]

    operations = [
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=255, unique=True)),
                ('filename', models.FileField(upload_to='upload/%Y%m%d')),
                ('time', models.CharField(default='0', max_length=255, unique=True)),
            ],
        ),
    ]