# Generated by Django 4.0.6 on 2022-08-10 15:39

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0009_key_filename'),
    ]

    operations = [
        migrations.AddField(
            model_name='key',
            name='create_time',
            field=models.DateTimeField(auto_now_add=True, default=datetime.datetime(2022, 8, 10, 15, 39, 55, 858019)),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='key',
            name='filename',
            field=models.FileField(upload_to='upload/%Y%m%d'),
        ),
    ]