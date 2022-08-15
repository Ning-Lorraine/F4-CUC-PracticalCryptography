#### 1 实现功能
1. 用户上传文件时，若文件名相同自动重命名
    - 设计逻辑：每一文件存入数据表时保存计数 `count` ，每当新文件上传时，与数据表中所有文件的文件名对比，若相同，原表中文件 `count` 值加1，以此记录相同文件名个数，新上传文件重命名为 `filename+(count)+文件后缀名`
    - 代码：
        ```python
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
        ```
1. 文件下载
   - 设计逻辑：本系统采用django框架，django实现下载可采用 `HttpResponse` , `StreamingHttpResponse` 以及 `FileResponse` , `Httpresponse` 对象初始化时会将文件内容载入内存：当文件过大时会大量占用服务器内存,故不采用。本系统采用 `StreamingHttpResponse` 流类型实现文件下载。
   - 代码：
        ```python
        filepath = os.path.join('./static/files/', str(filename))
            fp = open(filepath, 'rb')
            response = StreamingHttpResponse(fp)
            # response = FileResponse(fp)
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = 'attachment;filename="%s"' % escape_uri_path(str(filename))
            return response
            fp.close()
        ```
2. 匿名用户输入提取码下载文件，提取码自动填写
    - 设计逻辑：模拟百度网盘为分享文件生成提取码，匿名用户点击下载时自动输入提取码，也可手动修改，验证提取码正确即可成功下载。提取码通过返回 `render` 的参数由后端传至前端自动填写。
    - 代码：
        ```python
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
            return raw
        ```

3. 下载文件散列值
   - 设计逻辑：点击下载时，将文件的明文散列值写入 `static/hash` 文件夹，命名为 `filename+散列值.txt` 下载
   - 代码：
        ```python
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
        ```
4. 用户分享下载链接时选择限制访问次数或访问时间，过期链接失效、
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

#### 2 总结思考与改进
1. 及时本地以及 `github` 备份!!!!!!
    - 原本吸取 `Linux` 课程的经验，在虚拟机中备份了很多次快照，结果没想到在开发后期遇上虚拟机崩溃，镜像文件无法打开，之前开发的内容都存在虚拟机全部丢失。所以一定记得及时本地以及 `github` 备份才是最保险的操作。
2. 产品功能设计反思：
    - 我主要实现的下载以及分享 `url` 功能跳转的前端页面过多，设计逻辑较为复杂；这导致用户操作成本太大，体验可能不好，下次改进尽量减少用户操作，产品逻辑更符合用户使用习惯（又是梦想成为产品经理的一天）
3. 未解决的小问题：
    - 自动将分享链接复制至剪贴板无法实现，最开始调用 `win32clipboard` 库，但无法在 `linux` 服务器安装;查询资料后打算采用 `pyperclip` 或 `clipboard` 这两个跨平台实现复制粘贴的库，但其依赖的库无法在 `ubuntu 20.04` 的虚拟机安装，按照官方文档提供的办法未解决。最终通过前端界面写入js函数实现弹窗展示分享链接，由用户手动复制。
4. 密码学思考：
    - 本次访问控制 `url` 采用 `token` 实现，生成token时，进行消息摘要采用 `md5` 算法实现，但 `md5` 实际没有 `sha` 更加安全。老师在功能清单中也提到了 `hmac` ,查询学习后了解到 `hmac` 为使用单向散列函数来构造消息认证码，也可使用 `hmac` 实现服务器对访问者进行鉴权。
5.  `Django` 前后端传参方式总结:
    - 本次实现各功能时，最开始遇到的很多问题都是由于不熟悉 `Django` 前后端传参方式而导致的，故此处将本次用到的传参方式总结。
      - 前端传至后端：
        - 前端用表单形式提交，采用 `<input type="text" name="自己起个名"/>` 标签传递用户从前端输入的参数，点击 `<input type="submit"/>` 提交按钮，将该参数提交至表单 `action` 中写入的视图函数；通过 `request.POST.get('自己起个名')` 在后端视图函数获取参数
        - 前端通过 `url` 链接 `<a href="/视图函数名/？自己起个变量名={{想要传的参数}}">` 传递参数；后端通过 `request.GET.get('自己起个变量名')` 即可获得参数
      - 后端传至前端：
          例如，在视图函数中有个变量为 `a` 在视图函数中通过 `return render(request,'你想返回的html页面的相对路径')，{'再随便起个名'：a})` 即可将 `a` 传递至返回的 `html` 界面；在 `html` 界面直接用 `{{再随便起个名}}` 即可获得该变量
      - 后端传至前端，再从该前端传回后端的另一个视图函数：
          我用到的一个方法是，先通过上面 `后端传至前端` 的方法，将变量传至前端；若该前端采用到了表单形式提交，则可采用 `<input type="text" name="自己起个名" hidden value="{{刚才从后端传至前端的参数}}"/>` 进行提交，在前端把该内容隐藏，再通过表单的方式提交到后端。

#### 3 参考文档
- [Django 实现文件下载的几种方式](https://blog.csdn.net/qq_37674086/article/details/113351603)
- [Django 前端传递数据到后端处理 POST方法](https://blog.csdn.net/u013288190/article/details/117418093)
- [python 与系统剪贴板的交互](https://blog.csdn.net/weixin_40301746/article/details/123942176)
- [jquery点击按钮更改input的value值](https://blog.csdn.net/weixin_43488742/article/details/105577730?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-1-105577730-blog-89519772.pc_relevant_vip_default&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-1-105577730-blog-89519772.pc_relevant_vip_default&utm_relevant_index=1)
- [哈希算法和·Hmac算法 对称式与非对称式加密对比](https://blog.csdn.net/m0_66971047/article/details/125874665)
- [加密之单向MD5,SHA,HMAC](https://blog.csdn.net/u012060033/article/details/122304036)
- [python 产生token及token验证的方法](https://www.jb51.net/article/153525.htm)
- [django中的权限认证token和jwt实操记录](https://blog.csdn.net/qq_32656561/article/details/107933708?spm=1001.2101.3001.6650.2&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-2-107933708-blog-105087226.pc_relevant_vip_default&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-2-107933708-blog-105087226.pc_relevant_vip_default&utm_relevant_index=3)