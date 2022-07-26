# login/views.py
 
from django.shortcuts import render,redirect
from . import models
from .forms import UserForm,RegisterForm,FileForm
import hashlib
from django.http import HttpResponse
import os
from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey
import requests
from cryptography.fernet import Fernet

#from .models import User

 
 
def index(request):
    pass
    return render(request,'login/index.html')
 
def login(request):
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
                print(user)
                if user.password == hash_code(password):  # 哈希值和数据库内的值进行比对
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
        # 登录状态不允许注册。你可以修改这条原则！
        return redirect("/index/")
    if request.method == "POST":
        register_form = RegisterForm(request.POST)
        message = "请检查填写的内容！"
        if register_form.is_valid():  # 获取数据
            print(register_form.is_valid)
            username = register_form.cleaned_data['username']
            password1 = register_form.cleaned_data['password1']
            password2 = register_form.cleaned_data['password2']
            email = register_form.cleaned_data['email']
            #sex = register_form.cleaned_data['sex']
            if password1 != password2:  # 判断两次密码是否相同
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
                new_user.password = hash_code(password1)  # 使用加密密码
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


##对用户注册的密码加密
def hash_code(s, salt='mysite_login'):
    h = hashlib.sha256()
    s += salt
    h.update(s.encode())  # update方法只接收bytes类型
    return h.hexdigest()


def handle_upload_file(file, userfile):
    content = b''

    #生成会话密钥
    userfile.enckey = Fernet.generate_key()
    key = Fernet(userfile.enckey)

    #生成用户私钥、公钥
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    #序列化公钥以发给第三方
    verify_key_b64 = verify_key.encode(encoder=Base64Encoder)

    # 公钥私钥存储

    models.Key.objects.create(
        public_key = signing_key,
        secret_key = verify_key_b64,
    )

    with open("./static/files/%s" % '['+str(userfile.id)+']' , 'wb+') as f:
        for chunk in file.chunks():
            content += chunk
            # 先使用对称密钥加密，然后使用用户私钥签名存储
            c = key.encrypt(chunk)
            signed_b64 = signing_key.sign(b"c", encoder=Base64Encoder)
    # passlib中sha256输入最长为4096个字符，还没想到好的文件哈希方法，先前截取4096位
    userfile.sha256 = sha256_crypt.hash(str(content)[0:4096])  # str1.encode('utf-8')
    f.close()


def upload(request):
    if request.method == "GET":
        form=FileForm()
        return render(request,'login/upload.html',{'form':form})

    
    form=FileForm(data=request.POST,files=request.FILES) 
    file_object=request.FILES.get('avatar')
    if form.is_valid():
        content=b''
        print(form.cleaned_data)
        if file_object.size>10*1024*1024:
            return HttpResponse("文件过大! 请选择10MB以下的文件。")
        ftype = ['.jpg', '.png', '.jpeg', '.bmp', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']

        if os.path.splitext(file_object.name)[1] not in ftype:
            return HttpResponse("不支持的文件类型，仅支持jpg/jpeg/png/bmp以及office文件。")

        else:
            file_path=os.path.join('./static/files/',file_object.name)
            f=open('./static/files/'+file_object.name,mode='wb')
            for chunk in file_object.chunks():
                content+=chunk
                f.write(chunk)
            file_sha256 = hashlib.sha256(str(content).encode('utf-8')[0:4096]).hexdigest()
            f.close()

            file = models.File.objects.create(
                custom_filename=form.cleaned_data['username'],
                # username=request.session['user_name'],
                filename=file_object.name,
                size=file_object.size,
                sha256 = file_sha256
                )
            handle_upload_file(file_object.name,file)
        # file.username = request.session['user_name']
        # file.filename = request.FILES['filename'].name
        # file.size = request.FILES['filename'].size

    return render(request,'login/list.html')



def list(request):
    queryset=models.File.objects.all()

    for obj in queryset:
        print(obj.custom_filename,obj.filename,obj.size,obj.sha256,obj.create_time)
    return render(request,'login/list.html',{'queryset':queryset})

def delete(request):
    nid=request.GET.get('nid')
    models.File.objects.filter(id=nid).delete()

    return redirect('/list/')

def download():
    pass
    return render(request, 'login/download.html')


