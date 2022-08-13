from django.contrib import admin

# Register your models here.

###在admin中注册模型

from . import models
 
admin.site.register(models.User)