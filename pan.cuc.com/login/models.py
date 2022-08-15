from django.db import models
from django.utils import timezone

# Create your models here.

#数据库模型设计
# 作为一个用户登录和注册项目，需要保存的都是各种用户的相关信息。


class User(models.Model):
    '''用户表'''
    name = models.CharField(max_length=128,unique=False)    # 用户名
    password = models.CharField(max_length=256)             # 密码
    email = models.EmailField(unique=False)                 # 使用Django内置的邮箱类型，并且唯一
    c_time = models.DateTimeField(auto_now_add=True)
    public_key=models.CharField(max_length=256,default='')  # 用户公钥
    secret_key=models.CharField(max_length=256,default='')    
 
    def __str__(self):
        return self.name
 
    class Meta:
        ordering = ['c_time']
        verbose_name = '用户'
        verbose_name_plural = '用户'
        

class Key(models.Model):          
    filename = models.FileField(upload_to = 'upload/%Y%m%d',default='')
    session_key=models.CharField(max_length=256,default='')
    sign = models.CharField(max_length=256, default=' ')   # 数字签名  
    en_sha256=models.CharField(max_length=256, default=' ')     


class File(models.Model):
    '''文件'''
    user_name = models.CharField(max_length=128,unique=False,default='')   # 用户名
    custom_filename = models.CharField(max_length=128, unique=True)  # 上传自定义文件名
    filename = models.FileField(upload_to = 'upload/%Y%m%d')  # 文件名
    size = models.IntegerField(default=0)    # 文件大小
    sha256 = models.CharField(max_length=256, default=' ')  # 明文文件的sha256
    create_time = models.DateTimeField(auto_now_add=True)  # 上传时间
    keynumber = models.CharField(max_length=128,unique=False,default='')#随机生成提取码
    count = models.IntegerField(default=0) # 文件重复次数


    def __unicode__(self):
        return self.username

# 存储含有分享时长的token
class Token(models.Model):
    token = models.CharField(max_length=255,unique=True)
    filename = models.FileField(upload_to = 'upload/%Y%m%d') # 文件名
    time = models.CharField(max_length=255,unique=True,default='0') # 时间戳

# 存储含有分享次数的token
class Token2(models.Model):
    token = models.CharField(max_length=255,unique=True)
    filename = models.FileField(upload_to = 'upload/%Y%m%d') # 文件名
    share_numbers = models.IntegerField(unique=False,default=0)
    remain_numbers = models.IntegerField(unique=False,default=0)