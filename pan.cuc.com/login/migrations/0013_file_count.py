# Generated by Django 4.0.6 on 2022-08-13 16:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0012_token2'),
    ]

    operations = [
        migrations.AddField(
            model_name='file',
            name='count',
            field=models.IntegerField(default=0),
        ),
    ]
