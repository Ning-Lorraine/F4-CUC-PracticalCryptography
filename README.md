# 中传放心传

本项目是 [中国传媒大学密码学应用实践课程](https://c4pr1c3.github.io/cuc-wiki/ac.html) 第六组——F4小组的结课项目。

附上 [仓库链接](https://github.com/Ning-Lorraine/F4-CUC-PracticalCryptography)

## 功能清单

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
- 基于网页的文件上传加密与数字签名系统（20分）
  - [x] 已完成《基于网页的用户注册与登录系统》所有要求
  - [x] 限制文件大小：小于 10MB
  - [x] 限制文件类型：office文档、常见图片类型
  - [x] 匿名用户禁止上传文件
  - [x] 对文件进行对称加密存储到文件系统，禁止明文存储文件 【 对称加密 密钥管理（如何安全存储对称加密密钥） 对称加密密文的PADDING问题 】
  - [x] 系统对加密后文件进行数字签名 【 数字签名（多种签名工作模式差异） 】
- 基于网页的加密文件下载与解密（20分）
  - [x] 已完成《基于网页的文件上传加密与数字签名系统》所有要求
  - [x] 提供匿名用户加密后文件和关联的数字签名文件的下载
    - 客户端对下载后的文件进行数字签名验证 【 非对称（公钥）加密 数字签名 】
    - 客户端对下载后的文件可以解密还原到原始文件 【 对称解密 密钥管理 】
  - [x] 提供已登录用户解密后文件下载
  - [x] 下载URL设置有效期（限制时间或限制下载次数），过期后禁止访问 【 数字签名 消息认证码 Hash Extension Length Attack Hash算法与HMAC算法的区别与联系 】
  - [x] 提供静态文件的散列值下载，供下载文件完成后本地校验文件完整性 【 散列算法 】

## 本项目用到的关键技术

- 开发语言为Python3.8.10

- 后端基于Django 4.0.6框架

- 前端基于Bootstrap3 框架

  附上[Bootstrap3下载链接](https://v3.bootcss.com/getting-started/#download)和[jQuery下载链接](https://www.jq22.com/jquery-info122)

- 使用MySQL 8.0数据库

### 密码学理论与技术示范应用要点说明
| 密码学理论   | 技术应用 |   技术示范 |作用|
| :------------- | :----------: | :----------: | :----------: |
|哈希+盐值 | pbkdf2 | 用户口令加密 |保证用户密码安全性|
|  对称密钥|   nacl.secret   |  加密文件 | 存储加密文件防止明文被获取 |
| 非对称密钥  |    nacl.signing   | 数字签名|匿名用户验证分享链接用户身份|
|哈希摘要|hashlib|生成文件哈希值|验证下载的明文是否经过篡改|
|哈希摘要|md5|生成token消息摘要|实现散列值校验|
|哈希+数字签名|x.509证书|配置https|识别网页身份，保护数据传输安全|

## 快速上手体验

本项目通过 `sudo docker-compose up -d` 方式部署后

打开浏览器访问： [https://pan.cuc.com](https://pan.cuc.com) 即可快速体验系统所有功能。

### 依赖环境配置补充说明

- 安装docker-compose

  ```
  #确保 docker-compose 全局安装
  sudo apt install docker-compose
  ```

- 配置域名

  在宿主机与虚拟机中分别修改hosts文件，添加`127.0.0.1 pan.cuc.com`的映射关系

  - Windows环境中，文件位于`C:\Windows\System32\drivers\etc`
  - Ubuntu环境中，文件位于`/etc/hosts`

- 证书安装

  为建立安全连接，需要将cert目录下CARoot.crt，intermedia.crt证书添加至浏览器受信任的根证书，中间证书颁发机构列表中。

  ![](img/root.png)

  ![](img/intermedia.png)

## 演示

- [系统功能操作演示视频](https://www.bilibili.com/video/BV1LB4y1L72s?spm_id_from=333.999.0.0&vd_source=b6b417005a6423397884b3002dba82fc) 
- 因视频时长原因未能详细说明的问题以文字形式汇总为[问题清单](./问题清单.md)
