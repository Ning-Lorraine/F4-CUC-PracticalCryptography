# 中传放心传

本项目是 [中国传媒大学密码学应用实践课程](https://c4pr1c3.github.io/cuc-wiki/ac.html) 的一个作业项目。

## 实现功能清单

- 基于网页的用户注册与登录系统（60分）
  - [x] 使用https绑定证书到域名而非IP地址 【 *PKI* *X.509* 】
  - [x] 允许用户注册到系统
    - 用户名的合法字符集范围：中文、英文字母、数字
      - 类似：-、_、.等合法字符集范围之外的字符不允许使用
    - 用户口令长度限制在36个字符之内
    - 对用户输入的口令进行强度校验，禁止使用弱口令
  - [x] 使用合法用户名和口令登录系统
  - [x] 禁止使用明文存储用户口令 【 PBKDF2 散列算法 慢速散列 针对散列算法（如MD5、SHA1等）的攻击方法】
    - 存储的口令即使被公开，也无法还原/解码出原始明文口令

## 本项目用到的关键技术

- 开发语言为Python3.8.10

- 后端基于Django 4.0.6框架

- 前端基于Bootstrap3 框架

  附上[Bootstrap3下载链接](https://v3.bootcss.com/getting-started/#download)和[jQuery下载链接](https://www.jq22.com/jquery-info122)

- 使用MySQL 8.0数据库

## 快速上手体验

- 下载环境依赖并运行

  ```bash
  pipenv install
  pipenv shell
  ```

- 安装数据库

  ```bash
  sudo apt update
  sudo apt install mysql-server
  ```

- 对Mysql root用户数据库权限进行设置

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

- 运行

  ```bash
  python manage.py runserv_plus pan.cuc.com:8000 --cert app.crt --key-file app.key
  ```


## 附录

- 手动将CARoot.crt，intermedia.crt证书添加至浏览器收信人根证书，中间证书颁发机构列表，否则浏览器将视其为不安全连接

  ![](img/root.png)

  ![](img/intermedia.png)