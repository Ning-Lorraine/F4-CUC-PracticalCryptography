# login/views.py
from django.shortcuts import render,redirect
from . import models
from .forms import UserForm,RegisterForm,FileForm,KeyForm
import os
import re
from django.contrib.auth.hashers import make_password, check_password
#from .models import User
import hashlib
import nacl.secret
import nacl.utils
from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey
from nacl.signing import SigningKey
from django.http import StreamingHttpResponse
from django.utils.encoding import escape_uri_path
from django.views.decorators.csrf import csrf_exempt
import pickle
import random
import getpass

 
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

                signing_key = SigningKey.generate()
                verify_key = signing_key.verify_key

                
                #序列化公钥以发给第三方
                signing_key_bytes = signing_key.encode(encoder=HexEncoder)
                # print(signing_key_bytes,type(signing_key_bytes))
                verify_key_bytes = verify_key.encode(encoder=HexEncoder)

 
                new_user = models.User.objects.create()
                new_user.name = username
                #加盐
                new_user.salt = str(os.urandom(32))
                #django自带pbkdf2_SHA-256算法加密用户密码
                new_user.password = make_password(password1,new_user.salt,'pbkdf2_sha256')  # 使用加密密码
                new_user.email = email
                #new_user.sex = sex
                new_user.public_key = verify_key_bytes
                new_user.secret_key = signing_key_bytes
                new_user.save()
                return redirect('/login/')  # 自动跳转到登录页面
    register_form = RegisterForm()
    return render(request, 'login/register.html', locals())
 
def logout(request):
    if not request.session.get('is_login',None):
        return redirect('/index/')
    request.session.flush()
    return redirect('/index/')



def handle_upload_file(file,userfile,notes):
    content = b''

    #生成会话密钥
    s_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    s_key_string=str(s_key,encoding='ISO-8859-1')
    # print('********encode**********',len(s_key_string),type(s_key_string),s_key_string)
    key = nacl.secret.SecretBox(s_key)
    # key_64=key.encode(encoder=Base64Encoder)
    # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    
    # 加密存储
    with open('./static/files/'+file.name,mode='wb') as f:    
        for chunk in file.chunks():
            content+= chunk
            c = key.encrypt(chunk)
            # d=key.decrypt(c)
        pickle.dump(c, f)
            # f.write(d) 
    file_sha256 = hashlib.sha256(str(c).encode('utf-8')[0:4096]).hexdigest()
    print(file_sha256)
    models.Key.objects.create(
        filename=notes,
        session_key=s_key_string,
        en_sha256=file_sha256,
        # public_key = signing_key,
        # secret_key = verify_key_b64,
    )
    # d=key.decrypt(c)
    # print(d.decode('utf-8'))
    f.close()
    return (key)


import random
import string

# 生成随机提取码
def createRandomString(len):
    raw = ""
    range1 = range(58, 65) # between 0~9 and A~Z
    range2 = range(91, 97) # between A~Z and a~z

    i = 0
    while i < len:
        seed = random.randint(48, 122)
        if ((seed in range1) or (seed in range2)):
            continue
        raw += chr(seed)
        i += 1
    # print(raw)
    return raw

def upload(request):
    message=''
    form=FileForm(data=request.POST,files=request.FILES)
    file_object=request.FILES.get('avatar')
    
    if request.method == "GET":
        form=FileForm()
        return render(request,'login/upload.html',{'form':form})

    if request.method == "POST":
        if form.is_valid():
            content=b''
            print(form.cleaned_data)
            if file_object.size>10*1024*1024:
                return HttpResponse("文件过大! 请选择10MB以下的文件。")
            ftype = ['.jpg', '.png', '.jpeg', '.bmp', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']

            if os.path.splitext(file_object.name)[1] not in ftype:
                return HttpResponse("不支持的文件类型，仅支持jpg/jpeg/png/bmp以及office文件。")

            
            file_name=form.cleaned_data['username']
            same_custom_filename = models.File.objects.filter(custom_filename=file_name)
            if same_custom_filename:  # 用户名唯一
                message = '已存在相同的文件备注，请重新填写！'
                return render(request, 'login/upload.html', locals())

            else:
                same_filename = models.File.objects.filter(filename=file_object.name)
                if same_filename: #文件名重复
                    queryset=models.File.objects.all()
                    # num = 0
                    for obj in queryset:
                        if obj.filename == file_object.name:
                            obj.count = obj.count +1
                            obj.save()
                            num = obj.count
                    
                    str1='.'
                    str2=file_object.name[file_object.name.index(str1):]
                    file_object.name = file_object.name[:file_object.name.index(str1)]
                    file_object.name = file_object.name + '('+str(num)+')'+str2
                    file_path=os.path.join('./static/files/',file_object.name)
                else:
                    file_path=os.path.join('./static/files/',file_object.name)
                f=open('./static/files/'+file_object.name,mode='wb')
                for chunk in file_object.chunks():
                    content+=chunk
                    f.write(chunk)
                file_sha256 = hashlib.sha256(str(content).encode('utf-8')[0:4096]).hexdigest()
                # f.close()
                # username=str(request.user.username)
                # print(username)
                file = models.File.objects.create(
                    custom_filename=form.cleaned_data['username'],
                    user_name=request.POST.get('user'),
                    filename=file_object.name,
                    size=file_object.size,
                    sha256 = file_sha256,
                    keynumber = str(createRandomString(6))
                ) 
                handle_upload_file(file_object,file,file_name)
            # file.username = request.session['user_name']
            # file.filename = request.FILES['filename'].name
            # file.size = request.FILES['filename'].size

        else:
            message="文件备注不能为空"
            return render(request,'login/upload.html',{'message':message})
    return render(request,'login/list.html',{'form':form})



def sign_list(request):   
    queryset=models.User.objects.all()
    for obj in queryset:
        print(obj.name,obj.public_key,obj.secret_key)
    return render(request,'login/sign_list.html',{'queryset':queryset})



def sign(request):
    nid=request.GET.get('nid')
    queryset=models.User.objects.filter(id=nid)
    sha_queryset=models.Key.objects.values('en_sha256')
    for obj in queryset:
        p_key=obj.public_key
        s_key=obj.secret_key
        # for sha_obj in sha_queryset:

    # return render(request,'login/sign_list.html',{'queryset':queryset})
    return HttpResponse('签名成功！')


def list(request):
    queryset=models.File.objects.all()
    # queryset_user=models.User.objects.all()
    for obj in queryset:
        obj.user_name,obj.custom_filename,obj.filename,obj.size,obj.sha256,obj.create_time,obj.keynumber
    # for obj in queryset_user:
    #     obj.name
    # name=request.session.get('_auth_user_id')
    # print(name)
    return render(request,'login/list.html',{'queryset':queryset})

def delete(request):
    nid=request.GET.get('nid')
    models.File.objects.filter(id=nid).delete()

    return redirect('/list/')

def download(request):
    queryset=models.File.objects.all()

    for obj in queryset:
        obj.user_name,obj.custom_filename,obj.filename,obj.size,obj.sha256,obj.create_time
    return render(request,'login/download.html',{'queryset':queryset})

# 下载需要引入的库
from django.http import StreamingHttpResponse

# 中文无法下载问题 
from django.utils.encoding import escape_uri_path

# 提交时csrf报错
from django.views.decorators.csrf import csrf_exempt

def file_iterator(filename,chunk_size,s_key):
    s_key=bytes(s_key,encoding='ISO-8859-1')
    # print('***********decode*********',len(s_key),type(s_key),s_key)
    key = nacl.secret.SecretBox(s_key)
    # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    with open(filename,'rb') as f:
        while True:
            # c=f.read(chunk_size)
            c=pickle.load(f)
            text=key.decrypt(c)
            # for chunk in filename.chunks():
            #     content+= chunk
            #     text=key.decrypt(chunk)
            #     f.write(text.decode('utf-8')) 
            if c:
                yield text
            else:
                break
    f.close()
            
@csrf_exempt
def login_download(request):
    nid=request.GET.get('nid')
    queryset=models.File.objects.filter(id=nid)
    for obj in queryset:
        filename=obj.filename
        comment=obj.custom_filename
        filepath = os.path.join('./static/files/',str(filename))
        print(filepath)
        filesize=models.File.objects.get(custom_filename=comment).size
        # filesize=models.File.objects.get(custom_filename=comment).size
        key=models.Key.objects.get(filename=comment).session_key
        response = StreamingHttpResponse(file_iterator(filepath,filesize,key))
        # response = FileResponse(fp)
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = "attachment;filename*=utf-8''{}".format(escape_uri_path(str(filename)))
        return response
        fp.close()


import clipboard
import pyperclip

def logout_download(request):
    custom_filename=request.GET.get('custom_filename')
    user = models.File.objects.get(custom_filename=custom_filename)
    keynumber=user.keynumber
    # clipboard.copy("124")
    # print(custom_filename)
    return render(request, 'logout/verify.html',{'custom_filename':custom_filename,'keynumber':keynumber})

from django.contrib import messages

def logout_download_file(request):
    # 用户输入的提取码
    keynumber1=request.POST.get('keynumber')
    # request.getRequestURL()
    # user = models.File.objects.get(keynumber=keynumber1)
    custom_filename=request.POST.get('custom_filename')
    user = models.File.objects.get(custom_filename=custom_filename)
    # 系统中存储的提取码
    keynumber2=user.keynumber
    # print(user.keynumber)
    if keynumber1==keynumber2:
        queryset=models.File.objects.all()
        return render(request,'logout/file.html',{'queryset':queryset,'custom_filename':custom_filename,'user':user})
    else:
        message = "提取码输入错误！"
        return render(request, 'logout/verify.html',{'message':message,'custom_filename':custom_filename})


def logout_file_iterator(filename,chunk_size,s_key):
    s_key=bytes(s_key,encoding='ISO-8859-1')
    # print('***********decode*********',len(s_key),type(s_key),s_key)
    key = nacl.secret.SecretBox(s_key)
    # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    with open(filename,'rb') as f:
        while True:
            # c=f.read(chunk_size)
            c=pickle.load(f)
            text=key.decrypt(c)
            # for chunk in filename.chunks():
            #     content+= chunk
            #     text=key.decrypt(chunk)
            #     f.write(text.decode('utf-8')) 
            if c:
                yield text
            else:
                break
    f.close()

def handle_logout_download_file(request):
    custom_filename = request.GET.get('custom_filename')
    user = models.File.objects.get(custom_filename=custom_filename)
    filename = user.filename
    filesize=user.size
    key=models.Key.objects.get(filename=custom_filename).session_key
    filepath = os.path.join('./static/files/', str(filename))
    fp = open(filepath, 'rb')
    # response = StreamingHttpResponse(fp)
    response = StreamingHttpResponse(logout_file_iterator(filepath,filesize,key))
    # response = FileResponse(fp)
    response['Content-Type'] = 'application/octet-stream'
    # response['Content-Disposition'] =  "attachment;filename*=utf-8''{}" % escape_uri_path(str(filename))
    response['Content-Disposition'] = "attachment;filename*=utf-8''{}".format(escape_uri_path(str(filename)))
    return response
    fp.close()
    
def download_hash(request):
    custom_filename = request.GET.get('custom_filename')
    user = models.File.objects.get(custom_filename=custom_filename)
    hash = user.sha256
    # 将原文件扩展名变为txt
    filename=str(user.filename)
    str1='.'
    filename = filename[:filename.index(str1)]+'散列值.txt'
    
    # 将哈希值写进txt文件
    filepath="./static/hash/"+filename
    file = open(filepath,'w+')
    file.write(hash)
    file.close()
    fp = open(filepath, 'rb')
    response = StreamingHttpResponse(fp)
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="%s"' % escape_uri_path(filename)
    return response
    fp.close()


# # win32clipboard专门用来复制粘贴的
# import win32clipboard as wcb
# import win32con as wc
# def copy_url(url):
#     # 打开复制粘贴板
#     wcb.OpenClipboard()
#     # 我们之前可能已经Ctrl+C了，这里是清空目前Ctrl+C复制的内容。但是经过测试，这一步即使没有也无所谓
#     wcb.EmptyClipboard()
#     # 将内容写入复制粘贴板,第一个参数win32con.CF_TEXT不用管，我也不知道它是干什么的
#     # 关键第二个参数，就是我们要复制的内容，一定要传入字节
#     share_url = url
#     wcb.SetClipboardData(wc.CF_TEXT, "古明地觉世界第一可爱".encode("gbk"))
#     # 关闭复制粘贴板
#     wcb.CloseClipboard()
     


import time
import base64
import hmac


    
def share(request):
    filename = request.GET.get('file')
    return render(request,'login/share_choose.html',{'filename':filename})

def share_choose(request):
    choose =request.POST.get('choose')
    filename = request.POST.get('filename')
    if choose == 'num':
        return render(request,'login/share_num.html',{'filename':filename})
    if choose == 'time':
        return render(request,'login/share_time.html',{'filename':filename})
    else:
        message = "请设置选择分享方式！"
        return render(request, 'login/share_choose.html',{'message':message,'filename':filename})

def share_file_num(request):
    filename = request.POST.get('filename')
    share_numbers =request.POST.get('share_numbers')
    key= str(filename) # key设置成文件名
    token=''
    if share_numbers: 
            flag = 0
            token = build_num_token(key,share_numbers)
            #    将生成的含分享次数的token与文件名写入数据login_token2数据表
            share_token = models.Token2.objects.create(
                            token = token,
                            filename = filename,
                            share_numbers = share_numbers,
                            remain_numbers = share_numbers
                            )
    else:
        message = "请设置分享次数!"
        return render(request, 'login/share_num.html',{'message':message,'filename':filename})
    
    return render(request,'login/share_url.html',{'flag':flag,'token':token,'share_token':share_token})

def share_file_time(request):
    filename = request.POST.get('filename')
    out_time =request.POST.get('out_time')
    key= str(filename) # key设置成文件名
    token=''
    flag = 1
    if out_time: #设置分享时间
        if out_time =='3s':
             token = build_time_token(key,3)
        if out_time =='ten_mins':
             token = build_time_token(key,10*60)
        if out_time =='one_day':
            token = build_time_token(key,24*60*60)
        if out_time =='one_week':
            token = build_time_token(key,7*24*60*60)
        if out_time =='thirty_days':
            token = build_time_token(key,30*24*60*60)
        # 将生成的含分享时长的token与文件名写入数据login_token数据表
        share_token = models.Token.objects.create(
                        token = token,
                        filename = filename,
                        time = str(time.time())
                        ) 
    else:
        message = "请设置分享时长!"
        return render(request, 'login/share_time.html',{'message':message,'filename':filename})
    
    return render(request,'login/share_url.html',{'flag':flag,'token':token,'share_token':share_token})


# def share_file(request):
#     filename = request.POST.get('filename')
#     out_time =request.POST.get('out_time')

#     share_numbers =request.POST.get('share_numbers')
#     key= str(filename) # key设置成文件名
#     token=''
#     if out_time and share_numbers:
#         message = "仅支持设置分享次数或设置分享时长！"
#         return render(request, 'login/share.html',{'message':message,'filename':filename})



#     if out_time: #设置分享时间
#         flag = 1
#         if out_time =='3s':
#              token = build_time_token(key,3)
#         if out_time =='ten_mins':
#              token = build_time_token(key,10*60)
#         if out_time =='one_day':
#             token = build_time_token(key,24*60*60)
#         if out_time =='one_week':
#             token = build_time_token(key,7*24*60*60)
#         if out_time =='thirty_days':
#             token = build_time_token(key,30*24*60*60)
#         # 将生成的含分享时长的token与文件名写入数据login_token数据表
#         share_token = models.Token.objects.create(
#                         token = token,
#                         filename = filename,
#                         time = str(time.time())
#                         ) 
#         # time.sleep(4)
#     else:

#         if share_numbers: #设置分享次数
#             flag = 0
#             token = build_num_token(key,share_numbers)
#             #    将生成的含分享次数的token与文件名写入数据login_token2数据表
#             share_token = models.Token2.objects.create(
#                             token = token,
#                             filename = filename,
#                             share_numbers = share_numbers,
#                             remain_numbers = share_numbers
#                             )
#         else:
#             message = "请设置分享次数或分享时长!"
#             return render(request, 'login/share.html',{'message':message,'filename':filename})

#     # time.sleep(4)
#     # a = check_token(flag,token)

#     # return HttpResponse(str(a))
    
#     return render(request,'login/share_url.html',{'flag':flag,'token':token,'share_token':share_token})

# 摘要算法加密
def hax(str):
    if not isinstance(str,bytes): # 如果传入不是bytes类型，则转为bytes类型
      try:
        str = bytes(str,encoding="utf8")
      except BaseException as ex:
        raise ValueError("'%s'不可被转换为bytes类型"%str)
 
    md5 = hashlib.md5()
    # md5.update("天王盖地虎erafe23".encode(encoding='utf-8'))
    md5.update(str)
    # md5.update("992ksd上山打老虎da".encode(encoding='utf-8'))
    return md5.hexdigest()

# 生成含分享时长的token
def build_time_token(message,expire):

    hax_message = "%s:%s:%s"%(str(time.time()),message,str(time.time()+expire))

    hax_res = hax(hax_message)
    token = base64.urlsafe_b64encode(("%s:%s"%(hax_message,hax_res)).encode(encoding='utf-8'))
    return token.decode("utf-8")

# 验证token时间限制
def check_time_token(token):
    try:
      hax_res = base64.urlsafe_b64decode(token.encode("utf8")).decode("utf-8")
      message_list = hax_res.split(":")
      md5 = message_list.pop(-1)
      message = ':'.join(message_list)
    #   print(111111111111111111111111111111111111)
    #   print(message_list)
    #   print(md5)
    #   print(message)
    #   print(hax(message))
      if md5 != hax(message):
        # 加密内容如果与加密后的结果不符即token不合法
        return False
      else:
            if time.time() - float(message_list.pop(-1)) >0:
            # 超时返回False
                return False
            else:
            # token验证成功返回新的token
                # return build_token(message_list.pop(-1))
                return True

    except BaseException as ex:
      # 有异常表明验证失败或者传入参数不合法
        return False

# 生成含分享次数的token
def build_num_token(message,share_numbers):
    hax_message = "%s:%s:%s"%(str(time.time()),message,str(share_numbers))

    hax_res = hax(hax_message)
    token = base64.urlsafe_b64encode(("%s:%s"%(hax_message,hax_res)).encode(encoding='utf-8'))
    return token.decode("utf-8")

# # 验证token分享次数限制
def check_num_token(token,remain_numbers):
    try:
        hax_res = base64.urlsafe_b64decode(token.encode("utf8")).decode("utf-8")
        message_list = hax_res.split(":")
        md5 = message_list.pop(-1)
        message = ':'.join(message_list)
      
    #   print(111111111111111111111111111111111111)
    #   print(message_list)
    #   print(md5)
    #   print(message)
    #   print(hax(message))

    # filename=message_list.pop(1)
        if md5 != hax(message):
            # 加密内容如果与加密后的结果不符即token不合法
            return False  
        else:
            user = models.Token2.objects.get(token=token)
            if user.remain_numbers>0:
                # 每访问一次，数据库中剩余可访问次数减一
                user.remain_numbers=user.remain_numbers-1
                user.save()
                remain_numbers =user.remain_numbers
                print(remain_numbers)
                return True
            else:
                return False
    except BaseException as ex:
      # 有异常表明验证失败或者传入参数不合法
        return False


def get_share_url_time(request):
    token = request.GET.get('token')
    user1 = models.Token.objects.get(token=token)
    url = 'https://pan.cuc.com:8000/get_share_url_time/?token='
    filename=user1.filename
    user= models.File.objects.get(filename=filename)
    if check_time_token(token):
        return render(request,'login/get_share_url.html',{'user':user,'url':url,'token':token})
    else:
        # message = '分享链接已超时！'
        # return render(request,'login/share_url.html',{'flag':flag,'user':user,'message':message})
        return HttpResponse("分享链接已超时！")

def get_share_url_num(request):
    token = request.GET.get('token')
    filename = request.GET.get('filename')
    url = 'https://pan.cuc.com:8000/get_share_url_num/?token='
    user1 = models.Token2.objects.get(token=token) 
    filename=user1.filename
    remain_numbers=user1.remain_numbers
    user= models.File.objects.get(filename=filename)
    if check_num_token(token,remain_numbers):
        return render(request,'login/get_share_url.html',{'user':user,'url':url,'token':token})
    else:
        return HttpResponse("分享链接已超过访问次数！")






