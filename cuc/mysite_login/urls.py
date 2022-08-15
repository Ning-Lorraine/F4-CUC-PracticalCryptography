"""mysite_login URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import re_path as url,include


##原来
# urlpatterns = [
#     path('admin/', admin.site.urls),
# ]

####修改
#####考虑到登录系统属于站点的一级功能，为了直观和更易于接受，这里没有采用二级路由的方式，
# 而是在根路由下直接编写路由条目，同样也没有使用反向解析名（name参数）。
# from django.conf.urls import url（不同）
from login import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^index/', views.index),
    url(r'^login/', views.login),
    url(r'^register/', views.register),
    url(r'^logout/', views.logout),
    url(r'^upload/', views.upload),
    url(r'^list/', views.list),
    url(r'^delete/', views.delete),
    url(r'^download/', views.download),
    url(r'^sign_list/', views.sign_list),
    url(r'^login_download/', views.login_download),
    url(r'^logout_download/', views.logout_download),
    url(r'^logout_download_file/', views.logout_download_file),
    url(r'^handle_logout_download_file/', views.handle_logout_download_file),
    url(r'^download_hash/', views.download_hash),
    url(r'^share/', views.share),
    url(r'^share_choose/', views.share_choose),
    url(r'^share_file_num/', views.share_file_num),
    url(r'^share_file_time/', views.share_file_time),
    url(r'^get_share_url_time/', views.get_share_url_time),
    url(r'^get_share_url_num/', views.get_share_url_num),
    url(r'^captcha', include('captcha.urls')) , # 增加这一行
    url(r'',views.login),
]
