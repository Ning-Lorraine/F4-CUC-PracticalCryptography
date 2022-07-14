## 实现功能

- 基于网页的用户注册与登录系统（60分）
  - 使用https绑定证书到域名而非IP地址 【 *PKI* *X.509* 】
  - [x] 允许用户注册到系统
  - 用户名的合法字符集范围：中文、英文字母、数字
  - 类似：-、_、.等合法字符集范围之外的字符不允许使用
  - 用户口令长度限制在36个字符之内
  - 对用户输入的口令进行强度校验，禁止使用弱口令

### 环境与环境配置

- **开发语言为Python3.8.10**

- **后端基于Django 4.0.6框架**

  ```bash
  ####注意！！先用 django-admin --version 检查是否已经存在django库,Python3.8.10应该是有的，这步就不用做了
  pip3 install django==4.0.6
  ```

- **前端基于Bootstrap3 框架**

  附上[Bootstrap3下载链接](https://v3.bootcss.com/getting-started/#download)和[jQuery下载链接](https://www.jq22.com/jquery-info122)

- **使用Apache服务器做前端**

- **使用MySQL 8.0数据库**    

  ```bash
  sudo apt install mysql-server -y 
  #或者
  sudo apt update
  sudo apt install mysql-server
  ```

  对Mysql root用户数据库权限进行设置

  ```bash
  #查看mysql数据库自动设置的随机账户与密码
  sudo cat /etc/mysql/debian.cnf  
  #获得<user> 和 <password> 字段 ，使用这两个字段登录
  mysql  -u <user> -p
  Enter password: <password>
  
  #配置root
  update user set authentication_string='' where user='root'; 
  #为root设置密码
  alter user 'root'@'localhost' identified with mysql_native_password by '123456（自行设置）';
  
  #设置成功，退出
  quit;
  
  #重启
  service mysql restart
  
  #新建数据库django
  mysql>create database django DEFAULT CHARACTER SET utf8;
  ```

- pymsql-1.0.2库的安装 

  ```python
  pip3 install pymysql
  ```

- django-simple-captcha库：django开源的图形验证码模块

  ```bash
  pip install django-simple-captcha
  #因为有PIL依赖顺便检查一下有没有pil库
  pip install pillow
  ```

### 运行

- ```python
  python manage.py runserver
  ```