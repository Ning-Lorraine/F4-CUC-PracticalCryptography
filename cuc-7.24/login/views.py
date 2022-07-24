# login/views.py
 
from django.shortcuts import render,redirect
from . import models
from .forms import UserForm,RegisterForm
import os
import re
from django.contrib.auth.hashers import make_password, check_password
#from .models import User
 
def index(request):
    pass
    return render(request,'login/index.html')
 
def login(request):
    #判断登陆状态
    if request.session.get('is_login', None):
        return redirect("/index/")

    if request.method == "POST":
        login_form = UserForm(request.POST)
        message = "请检查填写的内容！"
        if login_form.is_valid():
            username = login_form.cleaned_data['username']
            password = login_form.cleaned_data['password']
            try:
                user = models.User.objects.get(name=username)
                # 哈希对比
                if check_password(password,user.password):  # 哈希值和数据库内的值进行比对
                    request.session['is_login'] = True
                    request.session['user_id'] = user.id
                    request.session['user_name'] = user.name
                    return redirect('/index/')
                else:
                    message = "密码不正确！"
            except:
                message = "用户不存在！"
        return render(request, 'login/login.html', locals())
 
    login_form = UserForm()
    return render(request, 'login/login.html', locals())
 
 
def register(request):
    if request.session.get('is_login', None):
        # 登录状态不允许注册。修改这条原则
        return redirect("/index/")
    if request.method == "POST":
        register_form = RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():  # 获取数据
            print(register_form.is_valid)
            username = register_form.cleaned_data['username']
            # 匹配数字、字母、中文和特殊字符
            p = re.compile(r'[0-9]*[a-z]*[A-Z]*[\u4e00-\u9fa5]*')
            if '' in p.findall(username)[:-1]:
                message = '用户名不合法，请重新输入！\n' \
                          '请注意：用户名仅可包含中文、英文字母、数字'
                return render(request, 'login/register.html', locals())
            password1 = register_form.cleaned_data['password1']
            password2 = register_form.cleaned_data['password2']
            email = register_form.cleaned_data['email']
            #sex = register_form.cleaned_data['sex']
            regex1 = re.compile(r'[a-z]+').search(password1)
            regex2 = re.compile(r'[A-Z]+').search(password1)
            regex3 = re.compile(r'[0-9]+').search(password1)
            if len(password1) < 8:
                message = "密码过短，至少8位，至多36位！"
                return render(request, 'login/register.html', locals())
            elif len(password1) > 36:
                message = "密码过长，至少8位，至多36位！"
                return render(request, 'login/register.html', locals())
            elif (regex1 == None)or(regex2 == None)or(regex3 == None):
                num = True
                if num :
                    message = '禁止使用弱口令！密码必须同时包含大、小写字母和数字。'
                    return render(request, 'login/register.html', locals())
            
            elif password1 != password2:  # 判断两次密码是否相同
                message = "两次输入的密码不同！"
                return render(request, 'login/register.html', locals())

            else:
                same_name_user = models.User.objects.filter(name=username)
                if same_name_user:  # 用户名唯一
                    message = '用户已经存在，请重新选择用户名！'
                    return render(request, 'login/register.html', locals())
                same_email_user = models.User.objects.filter(email=email)
                if same_email_user:  # 邮箱地址唯一
                    message = '该邮箱地址已被注册，请使用别的邮箱！'
                    return render(request, 'login/register.html', locals())
 
                # 当一切都OK的情况下，创建新用户
 
                new_user = models.User.objects.create()
                new_user.name = username
                #加盐
                new_user.salt = str(os.urandom(32))
                #django自带pbkdf2_SHA-256算法加密用户密码
                new_user.password = make_password(password1,new_user.salt,'pbkdf2_sha256')  # 使用加密密码
                new_user.email = email
                #new_user.sex = sex
                new_user.save()
                return redirect('/login/')  # 自动跳转到登录页面
    register_form = RegisterForm()
    return render(request, 'login/register.html', locals())
 
def logout(request):
    if not request.session.get('is_login',None):
        return redirect('/index/')
    request.session.flush()
    return redirect('/index/')