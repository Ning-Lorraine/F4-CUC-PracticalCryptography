# 问题清单

- **请总结你们的所有已完成功能点  😎**

  - 基于网页的用户注册与登录系统（60分）

    - [x] 使用 https 绑定证书到域名而非 IP 地址 【 *PKI* *X.509* 】
      - 用户名的合法字符集范围：中文、英文字母、数字
        - 类似：-、_、.等合法字符集范围之外的字符不允许使用
      - 用户口令长度限制在36个字符之内
      - 对用户输入的口令进行强度校验，禁止使用弱口令
    - [x] 使用合法用户名和口令登录系统
    - [x] 禁止使用明文存储用户口令 【 PBKDF2 散列算法】
      - 存储的口令即使被公开，也无法还原/解码出原始明文口令
  - 基于网页的文件上传加密与数字签名系统（20分）

    - [x] 已完成《基于网页的用户注册与登录系统》所有要求
    - [x] 限制文件大小：小于 10MB
    - [x] 限制文件类型：office文档、常见图片类型
    - [x] 匿名用户禁止上传文件
    - [x] 对文件进行对称加密存储到文件系统，禁止明文存储文件 【 对称加密 密钥管理（如何安全存储对称加密密钥） 对称加密密文的PADDING问题 】
    - [x] 系统对加密后文件进行数字签名 【 数字签名（多种签名工作模式差异 ）】
  - 基于网页的加密文件下载与解密（20分）
    - [x] 已完成《基于网页的文件上传加密与数字签名系统》所有要求
    - [x] 提供匿名用户加密后文件和关联的数字签名文件的下载
      - 客户端对下载后的文件进行数字签名验证 【 非对称（公钥）加密 数字签名 】
      - 客户端对下载后的文件可以解密还原到原始文件 【 对称解密 密钥管理 】
    - [x] 提供已登录用户解密后文件下载
    - [x] 下载URL设置有效期（限制时间或限制下载次数），过期后禁止访问 
    - [x] 提供静态文件的散列值下载，供下载文件完成后本地校验文件完整性 【 散列算法 】

- **X.509证书中各个字段含义、用途解释说明。🦝**

  - `X.509` 公钥证书标准已经随着时间的过去经过了修订，每一个继承版本的数据结构都保留了以前版本中存在的字段，并且增加了更多字段。

    此次实验采用`openssl`自签发了v3版本的X.509证书。

    版本1，2字段：

    | 字段             | 说明                                                         |
    | ---------------- | ------------------------------------------------------------ |
    | 版本             | 指定所编码证书的版本号。                                     |
    | 序列号           | 包含证书颁发机构 (CA) 分配给证书的一个唯一正整数。           |
    | 签名算法         | 包含一个对象标识符 (OID)，指定 CA 用于对证书进行签名的算法。 例如，1.2.840.113549.1.1.5 指定 SHA-1 哈希算法与来自 RSA 实验室的 RSA 加密算法结合使用。 |
    | 颁发者           | 包含创建和签名证书的 CA 的 X.500 可分辨名称 (DN)。           |
    | 有效期           | 指定证书有效的时间间隔。 到 2049 年末之前的日期使用协调世界时（格林威治标准时间）格式 (yymmddhhmmssz)。 2050 年 1 月 1 日开始的日期使用普通时间格式 (yyyymmddhhmmssz)。 |
    | 使用者           | 包含实体的 X.500 可分辨名称，该实体与证书中包含的公钥相关联。 |
    | 公钥             | 包含公钥和关联的算法信息。                                   |
    | 颁发者唯一标识符 | 包含一个唯一值，在一段时间内由不同的实体重用时可用于唯一标记证书颁发机构的 X.500 名称。 |
    | 使用者唯一标识符 | 包含一个唯一值，在一段时间内由不同的实体重用时可用于唯一标记证书使用者的 X.500 名称。 |

    版本3扩展：

    | 字段             | 说明                                                         |
    | ---------------- | ------------------------------------------------------------ |
    | 授权密钥标识符   | 标识证书颁发机构 (CA) 公钥，与用于签署证书的 CA 私钥对应。   |
    | 基本约束         | 指定实体是否可用作 CA，如果可以，则指定在证书链中该 CA 下可以存在的从属 CA 的数量。 |
    | 证书策略         | 指定颁发证书的策略和使用证书的目的。                         |
    | CRL 分发点       | 包含基本证书吊销列表 (CRL) 的 URI。                          |
    | 增强型密钥用法   | 指定证书中包含的公钥的使用方式。                             |
    | 颁发者备用名称   | 为证书请求颁发者指定一个或多个备用名称形式。                 |
    | 密钥用法         | 指定证书中包含的公钥可以执行的操作的限制。                   |
    | 名称约束         | 指定证书层次结构中所有使用者名称必须位于的命名空间。 扩展仅在 CA 证书中使用。 |
    | 策略约束         | 通过禁止策略映射或通过要求层次结构中的每个证书包含一个可接受的策略标识符来约束路径验证。 扩展仅在 CA 证书中使用。 |
    | 策略映射         | 指定与发证 CA 中的策略对应的从属 CA 中的策略。               |
    | 私钥使用周期     | 为私钥指定与私钥关联的证书不同的验证周期。                   |
    | 使用者可选名称   | 为证书请求使用者指定一个或多个备用名称形式。 示例备用形式包括电子邮件地址、DNS 名称、IP 地址和 URI。 |
    | 使用目录属性     | 传达标识属性，如证书使用者的国籍。 扩展值是 OID 值对序列。   |
    | 使用者密钥标识符 | 区分证书使用者持有的多个公钥。 扩展值一般是密钥的 SHA-1 哈希。 |

- **WEB服务器使用的证书和CA使用的证书有什么区别和联系？🦝**

  1. WEB服务器使用的是终端证书，CA使用的是根/中间证书

     终端证书用来确保加密传输数据的公钥不被篡改，而根/中间证书与终端证书形成证书链确保终端证书的合法性与可靠性。由根证书签发中间证书，中间证书再颁布终端证书

  2. WEB服务器使用的是SSL证书。SSL证书是一种由CA机构颁发的数字证书，具有服务器身份验证和数据传输加密功能，因其部署在服务器上，所以也被称为服务器证书。

     而CA机构可以颁发各种数字证书，其中包括SSL证书、邮件证书、加密证书、软件数字证书等等。换句话说，服务器使用的证书是CA所颁发证书中的其中一种。

- **简述你们的口令安全存储策略。🦝**

  - 基于 Hash+salt 的算法存储用户口令的问题在于 Hash 函数的运算非常快，虽然加盐让暴力攻击和彩虹表攻击的可行性大大减低，但现在攻击者能在非常快速的硬件（包括 GPU）上运行，如果**时间足够**，还是有很大几率完成暴力破解。

  - 本次实验采用pbkdf2_sha256算法加密用户口令，它同样基于 Hash 函数，也有 salt 机制，但是引入了**迭代因子**的概念，让处理速度变慢，减少爆破风险。具体实现代码如下：

    ```python
    #加盐
    new_user.salt = str(os.urandom(32))
    #使用django自带pbkdf2_SHA-256算法加密用户密码
    new_user.password = make_password(password1,new_user.salt,'pbkdf2_sha256') 
    
    #登录时
    check_password(password,user.password)
    ```

    注册时使用`django`自带`make_password`函数，将用户输入原始口令`password1`与所生成盐值`new_user.salt`通过`pbkdf2_sha256`算法生成加密口令`new_user.password`存储在后台数据库中，实现密文存储用户口令并且存储的口令即使被公开，也无法还原/解码出原始明文口令要求（Hash单向性）

- **你们是如何实现弱口令检测的？ 🦝**

  代码如下：

  ```python
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
  ```

  1. 通过对用户输入口令的长度检测，将口令长度范围限制在8~36位之间
  2. 通过正则表达式`re.compile().search()`编译查找用户所输入口令，分为数字，大、小写字母三个编译板块，其中有一个板块查找为空——即不包含数字，大、小写字母中的任何一种，if语句将判断口令为弱口令不予通过，所以只有同时包含数字，大、小写字母的口令才能通过检测。

- **你们是如何实现安全的文件上传的？ 🐏** 

  - 这次文件上传使用的PyNacl这个密码学库，它是一个先进并且可用性、安全性较高的库。在上传文件时，我们每提交一个文件，就会通过pynacl.secret生成一个会话密钥。
    通过三行代码可知，通过`s_key`可以生成一个`key`，这个安全组合必须保密，因为通过它可以生成对称密钥进行加密和解密。
  - 我们在数据库里存储`s_key`方便在解密时生成相应的会话密钥用来解密。在存储密钥时，我们在存储`s_key`和`key`之间纠结了一下：存储`s_key`在解密时方便生成对应的会话密钥，用来解密比较轻松；存储`key`比较安全，因为即便`key`被获取也无法使用`key`生成会话密钥来解密。但是最终选择了存储`s_key`，需要对`s_key`进行转码存储，这样下载时方便提取，但是前提是要确保数据库所有内容不易被获取（数据库安全加密）；
  - 这样在下载文件时时，后端先使用注册用户的私钥解密获得`s_key`，然后再生成相应的会话密钥`key`，之后再使用`key`获取到明文；非注册用户在下载文件时，后端通过识别该文件上传的用户，然后调用该用户的私钥解密后生成会话密钥，最终解密密文获取明文。

- 请展示并说明你们的
  - **文件加密代码片段 🐏** 

    - 文件加密，使用PyNacl生成会话密钥
      ```python
      # This must be kept secret, this is the combination to your safe
      s_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
      s_key_string=str(s_key,encoding='ISO-8859-1')
      
      # This is your safe, you can use it to encrypt or decrypt messages
      key = nacl.secret.SecretBox(s_key)
      ```
    - 分块读入文件，并进行加密（需要使用序列化存储，方便之后解密进行解码）
      ```python
      with open('./static/files/'+file.name,mode='wb') as f:    
          for chunk in file.chunks():
              c = key.encrypt(chunk)
              content += c
          pickle.dump(content, f) # 序列化存储
      ````
    
  - **文件解密代码片段 🐏** 
    
    - 解密函数
      ```python
      # s_key是download函数里传入的密钥，这个密钥是从数据库中获取得到的安全组合
      def file_iterator(filename,chunk_size,s_key):
        s_key=bytes(s_key,encoding='ISO-8859-1')
      
        # 生成会话密钥
        key = nacl.secret.SecretBox(s_key)
      
        # 逆序列化分块读取文件并且对密文进行解密
        with open(filename,'rb') as f:
            while True:
                c=pickle.load(f)
                text=key.decrypt(c)
                if c:
                    yield text
                else:
                    break
        f.close()
      ```
    
  - **文件签名代码片段 😎**

    对称加密后的文件进行哈希运算，对得到的散列值用上传用户的私钥进行数字签名。

    ```python
    # 对加密文件进行哈希运算，得到摘要
    file_sha256 = hashlib.sha256(str(content).encode('utf-8')[0:4096]).hexdigest()
    file_sha256_bytes = bytes(file_sha256,encoding='ISO-8859-1')  # bytes类型
    
    # 数字签名：对加密后的文件的散列值进行签名
    signing_key_str = models.User.objects.get(name=username).secret_key 
    # 私钥
    signing_key = nacl.signing.SigningKey(signing_key_str, encoder=HexEncoder)  
    # 签名
    sha256_sign = signing_key.sign(file_sha256_bytes, encoder=HexEncoder)        
    sha256_sign = str(sha256_sign,encoding='ISO-8859-1')      # str类型
    ```

    用户的公私钥对使用 pynacl 密码库的内置函数生成。

    ```python
    signing_key = SigningKey.generate()   # 私钥
    verify_key = signing_key.verify_key	  # 公钥
    ```

  - **文件签名验证代码片段 😎**

    匿名用户下载文件时输入对应公钥，若公钥不能正确解密数字签名，则给出提示信息，若能正确解密，则可以验证系统的身份。

    ```python
    # 输入的公钥
    public_key_str = request.POST.get('pubilckey')
    pubilc_key_bytes = bytes(public_key_str,encoding='ISO-8859-1')
    public_key = VerifyKey(pubilc_key_bytes,encoder=HexEncoder)   # 获得公钥
    
    # 获得数字签名
    sign_str = models.Key.objects.get(filename=custom_filename).sign
    sign = bytes(sign_str,encoding='ISO-8859-1')
    # print(sign,len(sign),type(sign))
    
    # 解密数字签名
    try:
    	file_sha256 = public_key.verify(sign,encoder=HexEncoder)
    except:
        message = '数字签名验证失败，可能是公钥输入错误，不下载文件。'
        return render(request,'logout/signature.html',{'message':message})
    ```

  - **文件完整性验证代码片段 😎**

    数字签名验证过程中，匿名用户用公钥正确解密得到散列值后，计算密文的散列值，两者进行比对，若相等，则可验证文件的完整性，用户下载解密后的文件。若不相等，则文件存在安全隐患，用户下载加密文件。

    ```python
    # 调取对应加密文件
    filepath = os.path.join('./static/files/', str(filename))
    
    content = b''  
    with open(filepath,'rb') as f:
        c = pickle.load(f)
        content += c
         
    # 对加密文件进行hash计算散列值
    fp_sha256 = hashlib.sha256(str(content).encode('utf-8')[0:4096]).hexdigest()
    
    # 对比
    if file_sha256 != fp_sha256 :
        response = StreamingHttpResponse(fp)
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = "attachment;filename*=utf8''{}".format(escape_uri_path(str(filename)))
        return response
        fp.close()        
    elif file_sha256 == fp_sha256 :
    	key=models.Key.objects.get(filename=custom_filename).session_key  # 获得会话密钥
        response = StreamingHttpResponse(logout_file_iterator(filepath,filesize,key))  # 解密
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = "attachment;filename*=utf-8''{}".format(escape_uri_path(str(filename)))
        return response
        fp.close()
    ```

    提供静态文件的散列值下载，供下载文件完成后本地校验文件完整性 。

    ```python
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
    ```

- **同一个用户的不同文件是否使用相同的对称加密密钥？如果是，请说明其中存在的安全风险。如果否，请结合代码展示你们的文件对称加密密钥的存储和提取使用策略  🐏** 

  - 同一个用户上传的不同文件使用的是不同的会话密钥
    - 存储过程，将生成会话密钥的安全组合转码后存入数据库Key中，方便解密时提取并生成对应的会话密钥。
      ```python
      # 提交文件函数
      def handle_upload_file(file,userfile,notes):
        content = b''
      
        # 每提交一个文件就会生成一串密钥
        s_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        s_key_string=str(s_key,encoding='ISO-8859-1')
        key = nacl.secret.SecretBox(s_key)
        with open('./static/files/'+file.name,mode='wb') as f:    
            for chunk in file.chunks():
                content+= chunk
                c = key.encrypt(chunk)
            pickle.dump(c, f)
        file_sha256 = hashlib.sha256(str(c).encode('utf-8')[0:4096]).hexdigest()
        f.close()
      
        # 存储密钥
        models.Key.objects.create(
            filename=notes,
            session_key=s_key_string,
            en_sha256=file_sha256,
        )
        return ()
      ```
      Key对应的数据库
      ```python
        class Key(models.Model):        
          filename = models.FileField(upload_to = 'upload/%Y%m%d',default='')
          session_key=models.CharField(max_length=256,default='')  
          en_sha256=models.CharField(max_length=256, default=' ') 
      ```
    - 提取过程（以注册用户解密为例），在点击“下载”按钮的时候获取id，因为id唯一，所以可以获取到File数据库中对应的数据，考虑到需要获取密钥key，所以还应该将Key数据库和File数据库通过某一个相同的列链接，考虑到备注名`custom_filename`唯一并且是两个数据库重合的列，所以通过获取File数据库中的备注名获取Key数据库中的安全组合，最后生成解密文件对应的会话密钥。
      ```python
      @csrf_exempt
      def login_download(request):
          # 在下载时定位到文件id（id是唯一的）
          nid=request.GET.get('nid')
          queryset=models.File.objects.filter(id=nid)
          for obj in queryset:
            filename=obj.filename
            # 获取备注名custom_filename
            comment=obj.custom_filename
            filepath = os.path.join('./static/files/',str(filename))
            print(filepath)
            filesize=models.File.objects.get(custom_filename=comment).size
            key=models.Key.objects.get(filename=comment).session_key
            response = StreamingHttpResponse(file_iterator(filepath,filesize,key))
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = "attachment;filename*=utf-8''{}".format(escape_uri_path(str(filename)))
            return response
            fp.close()
      ```
      File数据库，其中的`custom_filename`和Key数据库中的`filename`相对应。
      ```python
        class File(models.Model):
          '''文件'''
          user_name = models.CharField(max_length=128,unique=False,default='')            #用户名
          custom_filename = models.CharField(max_length=128, unique=True)  # 上传自定义文件名
          filename = models.FileField(upload_to = 'upload/%Y%m%d')  # 文件名
          size = models.IntegerField(default=0)    # 文件大小
          sha256 = models.CharField(max_length=256, default=' ')  # 明文文件的sha256
          create_time = models.DateTimeField(auto_now_add=True)  # 上传时间
          keynumber = models.CharField(max_length=128,unique=False,default='')#随机生成提取码
          count = models.IntegerField(default=0) # 文件重复次数
      ```

- **你们的文件下载过期策略是如何设计并实现的？💃**

  - 设计逻辑：用户通过前端界面选择限制方式，后端调用不同的生成链接及验证函数

    - 访问控制原理：
      采用 `token` 实现文件下载分享 `url` 的访问控制。每次创建分享链接时为该次分享生成 `token` ， `token` 中传递分享的文件名称以及限制条件。每次访问该链接时验证 `token` ，未过期时允许访问，过期禁止访问。
    - 限制访问时间 `token` 生成及验证方式：
      -  `token` 生成：
         将文件分享时的当前时间戳、用户给定的 `key` （本系统 `key` 为文件数据库中存储的唯一 `filename` )、最大过期时间戳通过":"拼接，用 `md5` 算法产生消息摘要；将此消息摘要和消息本身通过":"拼接，再进行 `base64` 编码，生成最终的 `token` 。
      -  `token` 验证：
         将 `token` 通过 `base64` 解码后，计算获得消息的摘要值，与消息摘要进行对比，若满足则认为 `token` 合法；将当前时间戳与传来的最大过期时间戳对比，若未超时则认为 `token` 未过期，允许访问链接，否则拒绝访问，前端页面弹窗提示。
    - 限制访问次数 `token` 生成及验证方式：
          -  `token` 生成：
            将文件分享时的当前时间戳、用户给定的 `key` （本系统 `key` 为文件数据库中存储的唯一 `filename` )、用户输入的分享次数通过":"拼接，用 `md5` 算法产生消息摘要；将此消息摘要和消息本身通过":"拼接，再进行 `base64` 编码，生成最终的 `token` ；在数据库中创建表 `Token2` ，将 `token` 与分享次数 `share_numbers` 、剩余分享次数 `remain_numbers` 存入数据表，剩余分享次数 `remain_numbers` 第一次存入时与 `share_numbers` 相同。
          -  `token` 认证：
            将 `token` 通过 `base64` 解码后，计算获得消息的摘要值，与消息摘要进行对比，若满足则认为token合法；在数据库中查找表 `Token2` 中 `token` 值符合的该条数据，将其 `remain_numbers` 减1并保存;验证 `remain_numbers` 是否大于0，若大于0则该 `token` 未过期，允许访问链接，否则拒绝访问，前端页面弹窗提示。

  - 代码：

    - 摘要算法加密

      ```python
      def hax(str):
          if not isinstance(str,bytes): # 如果传入不是bytes类型，则转为bytes类型
          try:
              str = bytes(str,encoding="utf8")
          except BaseException as ex:
              raise ValueError("'%s'不可被转换为bytes类型"%str)
      
          md5 = hashlib.md5()
          md5.update(str)
      ```

    - 限制访问时间token生成及验证

      ```python
      # token生成
      def build_time_token(message,expire):
          hax_message = "%s:%s:%s"%(str(time.time()),message,str(time.time()+expire))
      
          hax_res = hax(hax_message)
          token = base64.urlsafe_b64encode(("%s:%s"%(hax_message,hax_res)).encode(encoding='utf-8'))
          return token.decode("utf-8")
      
      # token认证
      def check_time_token(token):
      try:
        hax_res = base64.urlsafe_b64decode(token.encode("utf8")).decode("utf-8")
        message_list = hax_res.split(":")
        md5 = message_list.pop(-1)
        message = ':'.join(message_list)
        if md5 != hax(message):
          # 加密内容如果与加密后的结果不符即token不合法
          return False
        else:
              if time.time() - float(message_list.pop(-1)) >0:
              # 超时返回False
                  return False
              else:
              # token验证成功返回True
                  return True
      
      except BaseException as ex:
        # 有异常表明验证失败或者传入参数不合法
          return False
      ```

    - 访问次数token生成及验证

      ```python
      # token生成
      def build_num_token(message,share_numbers):
          hax_message = "%s:%s:%s"%(str(time.time()),message,str(share_numbers))
      
          hax_res = hax(hax_message)
          token = base64.urlsafe_b64encode(("%s:%s"%(hax_message,hax_res)).encode(encoding='utf-8'))
          return token.decode("utf-8")
      
      # token认证
      def check_num_token(token,remain_numbers):
          try:
              hax_res = base64.urlsafe_b64decode(token.encode("utf8")).decode("utf-8")
              message_list = hax_res.split(":")
              md5 = message_list.pop(-1)
              message = ':'.join(message_list)
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
      ```

- **常见对称加密工作模式有哪些？各自应用场景、优缺点说明。💃**

  1. 电码本（ECB）模式
     - 描述：用相同密钥分别对明文组加密
     - 应用场景： 主要用于发送很少明文分组时。例如 ，用主密钥加密会话密钥。
     - 优点
       - 可以并行运算
       - 适用于随机存储的数据
     - 缺点
       - 当明文分组重复时，密文也重复，易实现统计分析攻击
       - 结构化数据，将产生大量重复的密文
       - 难以抵抗选取部分分组进行重放攻击，特别是针对按分组格式化的数据，必须辅助以消息认证来保证完整性

  2. 密文分组链接（CBC）模式
     - 描述：加密算法的输入是上一个密文组和本次明文组的异或
     - 应用场景：普通目的的面向分组的传输；认证
     - 优点
       - 不容易主动攻击，适合传输长度长的报文，安全性好于ECB
       - 没有明文错误传播，密文错误传播只影响本组以及后一组解密
     - 缺点
       - 加密过程是串行的，无法并行进行
       - 每个密文块依赖于所有的信息块，明文消息中一个改变会影响所有密文块

  3. 密文反馈（CFB）模式
     - 描述：上一块密文作为加密算法的输入，产生j位伪随机数与明文异或
     - 应用场景：适用于低误码率网络中流数据加密、认证；适用于数据以比特/字节为单位的场合
     - 优点
       - 自同步能力强，可以处理任意长度的消息
     - 缺点
       - 明文的一个错误会影响后面所有的密文，密文的一位错误，只影响明文的一个分组
       - 只有一个IV，可能影响安全性

  4. 输出反馈（OFB）模式
     - 描述：与CFB基本相同，只是加密算法的输入是上次DES的输出
     - 应用场景：噪声频道上的数据流的传输（如卫星通信）
     - 优点
       - 传输过程中的密文比特错误不会被传播
     - 缺点
       - 比CFB模式更易受到对消息流的篡改攻击

  5. 计数器（CTR）模式
     - 描述：每个明文分组都与一个加密计数器相异或。对每个后续分组计数器递增。
     - 应用场景：普通目的的面向分组的传输；用于高速需求
     - 优点
       - 高效，可预先处理（密钥流）；可并行处理各加密单元
       - 可随机解密任何密文分组，无需顺序解密
       - 可证明与其他模式同样安全
       - 结构简单，不需要解密算法
     - 缺点
       - 通信双方必须同步，否则难以解密

- **简述RSA加密算法和RSA签名算法之间的关系？ 💃**

  - 加解密算法：
    客户端和服务端进行通信加密,服务端要先生成一对RSA密钥,服务端自己持有私钥,给客户端公钥 —>客户端使用服务端的公钥加密要发送的内容,然后服务端接收到密文后通过自己的私钥解密内容

  - 签名验证算法：
    客户端给服务端发送消息,客户端先计算出消息的消息摘要,然后使用自己的私钥加密消息摘要,被加密的消息摘要就是签名。(客户端用自己的私钥给消息摘要加密成为签名)

    服务端收到消息后,也会使用和客户端相同的方法提取消息摘要,然后用客户端的公钥解密签名,并与自己计算出来的消息摘要进行比较–>如果相同则说明消息是客户端发送给B的,同时,客户端也无法否认自己发送消息给服务端的事实.(服务端使用客户端的公钥解密签名文件的过程,叫做"验签")。

  - 联系：
    在加密时使用公钥加密，私钥解密；在签名时使用私钥加密，公钥解密。

- **通过 PHP / Python 实现文件散列值计算有哪些方法？ 😎**

  系统中我们采用密码库 hashlib 的内置函数 sha256 和 md5 实现散列值的计算，调用方式为 `hashlib.sha256()`、`hashlib.md5()` 用同样的方式可以实现 sha1 、sha2、sha512 等哈希算法。

  ```python
  import hashlib
  
  obj = hashlib.md5()
  obj.update("< content >".encode("utf-8"))  # update 指定加密内容，encode 指定编码方式
  result=obj.hexdigest()   # hexdigest 将散列值转换为16进制
  ```

  此外，python 还有一个 hmac 模块，它内部对创建 key 和内容进行进一步的处理然后再加密。

  ```python
  import hmac
  
  h = hmac.new('salt'.encode('utf8'))         # hmac 必须要加盐
  h.update('<content>'.encode('utf8'))		# update 指定加密内容，encode 指定编码方式
  print(h.hexdigest())             
  
  # hmac 可以实现校验内容的累加
  h1 = hmac.new('salt'.encode('utf8'))
  h1.update('hello'.encode('utf8'))
  h1.update('world'.encode('utf8'))
  print(h1.hexdigest()) 
  
  h2 = hmac.new('salt'.encode('utf8'))
  h2.update('helloworld'.encode('utf8'))
  print(h2.hexdigest())
  # 二者输出的结果相同
  
  #	要想保证 hmac 最终结果一致，必须保证：
  #	1.hmac.new括号内指定的初始 key 一样
  #	2.保证 update 校验的内容累加到一起是一样的内容
  ```

- **你们是如何实现匿名用户禁止上传文件功能的？ 🐏** 

  - 主要是通过控制前端实现匿名用户禁止上传文件
    - 使用`request.session.is_login`判断是否处于登录状态，如果处在登录状态就显示上传界面，如果并不处于登录状态，就返回提示页面，禁止非注册用户进行文件上传。
      ```html
      {{% block content %}
      <div class="container">
          <div class="col-md-4 col-md-offset-4">
                  {% if request.session.is_login %}
                      <h1>你好,{{ request.session.user_name }}！<br></h1>
                      <h2>请选择上传文件！</h2>
                      <br>
                      <form method="post" action="" enctype="multipart/form-data">
                          {% if message %}
                              <div class="alert alert-warning">{{ message }}</div>  
                          {% endif %}
                          {{uf}}
                          {% csrf_token %}
                          <input type="text" name="username">
                          <input type="file" name="avatar">
                          <input type="text" name="user" hidden value="{{request.session.user_name}}"/>
                          <input type="submit" value="上传"/>
                      </form>
                  {% else %}
                      <h1>你尚未登录，不可以访问哦！</h1>
                  {% endif %}
          </div>
      </div> 
      {% endblock %}
      ```

- **请展示并说明你们的数据库表结构设计  😎**

  ## 

  - ```mysql
    +----------------------------+
    | Tables_in_django           |    
    +----------------------------+ 
    | auth_group                 |    # 组的 id 和组名称
    | auth_group_permissions     |    # 组的权限
    | auth_permission            |	  # 用户(管理员)所有的权限
    | auth_user                  |	  # 用户(管理员)：包括口令、姓名、邮箱的具体信息
    | auth_user_groups           |	  # 记录用户从属组的信息
    | auth_user_user_permissions |	  # 记录用户(管理员)拥有的权限
    | captcha_captchastore       |    # 验证码信息。记录验证码的内容、散列值和创建时间
    | django_admin_log           |    # 项目定义的数据库表结构映射到数据库中的操作日志
    | django_content_type        |    # 项目中所有model所属的app以及model的名字
    | django_migrations          |    # 项目定义的数据库表结构映射到数据库中的操作日志
    | django_session             |    # 保存用户的session信息
    | login_file                 |    # 上传文件的具体信息
    | login_key                  |    # 文件的秘密信息，包括会话密钥、密文散列值和数字签名
    | login_token                |    # 文件的token信息，记录下载url的限制时间
    | login_token2               |	  # 文件的token信息，记录下载url的限制次数
    | login_user                 |    # 用户表，保存用户的注册信息和系统分配的公私钥对
    +----------------------------+
    ```
