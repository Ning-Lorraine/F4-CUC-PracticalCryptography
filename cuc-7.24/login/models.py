from django.db import models

# Create your models here.

#数据库模型设计
# 作为一个用户登录和注册项目，需要保存的都是各种用户的相关信息。
# 我们至少需要一张用户表User，在用户表里需要保存下面的信息：


class User(models.Model):
    '''用户表'''
 
    name = models.CharField(max_length=128,unique=False)            #用户名
    password = models.CharField(max_length=256)                    #密码
    email = models.EmailField(unique=False)                         #使用Django内置的邮箱类型，并且唯一
    # sex = models.CharField(max_length=32,choices=gender,default='男')
    c_time = models.DateTimeField(auto_now_add=True)
 
    def __str__(self):
        return self.name
 
    class Meta:
        ordering = ['c_time']
        verbose_name = '用户'
        verbose_name_plural = '用户'


