[TOC]

# Google令牌

## #0 github

```
https://github.com/Coxhuang/google-authenticator.git
```

## #1 使用操作

- 调用绑定google-authenticator的接口,生成一个二维码(如何生成先不用管,后面再说)
- 手机客户端扫描二维码,App生成一个动态的6位验证码
- 输入验证码,返回True/False




## #2 原理

Google令牌分成两部分,一部分是服务端(Google提供的开源代码),另一部分就是客户端(用户在手机/电脑上安装的app或者插件)



- (服务端)随机生成一个字符串,并将该字符串+用户唯一标示(这里我用的用户唯一标示是邮箱)构造成固定的格式生成一个二维码
- (客户端)手机下载google-authenticator客户端,扫描二维码,二维码的信息(字符串+用户唯一标示)会保存在客户端内,App通过算法生成一个6位的验证码(验证码会通过时间的变化,30秒更新一次)
- (服务端)服务端使用Google提供的代码,把App提供的验证码+邮箱进行校验

## #3 实例讲解

### 需求分析

- 用户登陆时,除了需要用户名和密码,还需要提供该用户对应的Google令牌验证码

### 使用步骤

#### 新增用户(跳过这一步骤)
#### 绑定google-authenticator

调用绑定令牌接口效果图
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109153833133.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0NveGh1YW5n,size_16,color_FFFFFF,t_70)

拿返回的数据生成二维码,因为是前后端分离的项目,所以生成二维码交给前端处理,我这里使用网上在线生成二维码工具(https://cli.im/text?3dd4ec76bb965fb69effefc6a95b8ff8)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109153851908.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0NveGh1YW5n,size_16,color_FFFFFF,t_70)

使用手机App扫描二维码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109153911841.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0NveGh1YW5n,size_16,color_FFFFFF,t_70)

登陆

输入错误的令牌

![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109153927141.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0NveGh1YW5n,size_16,color_FFFFFF,t_70)

输入正确的令牌,会生成token,也就是登陆成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109153937543.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0NveGh1YW5n,size_16,color_FFFFFF,t_70)



## #4 具体代码讲解(本例子是前后端分离项目,只考虑后端,前端代码忽略,后端代码基于Django RestFramework)
### #4.1 需求分析
- 在用户登陆时,除了需要用户提供账号密码,还需要用户提供该用户实时的令牌验证码
- 登陆成功返回TOKEN

### #4.2 绑定令牌

先上代码
```
class googleSerializer(DynamicFieldsMixin,serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField()
    class Meta:
        model = models.UserProfile
        fields = ["username","password",]
    def validate_username(self, username):
        user = authenticate(username=username, password=self.initial_data["password"]) # 验证需要绑定令牌的用户账号密码是否[匹配
        if not user:
            raise Http404("账号密码不匹配")
        return username

class googleBindAPI(APIView):
    def post(self,request):
        queryset = models.Google2Auth.objects.filter(Q(user__username=request.data["username"]) | Q(user__email=request.data["username"]))
        if queryset.exists():
            return Response({"success": False, "msg": "已经绑定令牌,绑定失败", "results": None},status=status.HTTP_400_BAD_REQUEST)
        serializer = googleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = models.UserProfile.objects.get(Q(email=request.data["username"]) | Q(username=request.data["username"]))
        login(request, user)
        base_32_secret = base64.b32encode(codecs.decode(codecs.encode('{0:020x}'.format(random.getrandbits(80))), 'hex_codec'))
        totp_obj = googletotp.TOTP(base_32_secret.decode("utf-8"))
        qr_code = re.sub(r'=+$', '', totp_obj.provisioning_uri(request.user.email))
        models.Google2Auth.objects.create(user=user)
        key = str(base_32_secret,encoding="utf-8")
        queryset.update(key=key)
        return Response({"success": True, "msg": "绑定成功","results": {"将此数据生成二维码": qr_code}}, status=status.HTTP_201_CREATED)
```

请求头数据(用户名+密码)

```
{
	"username":"user",
	"password":"cox123456"
}
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109153951444.png)

表结构

```
class Google2Auth(models.Model):
    user = models.OneToOneField(UserProfile,on_delete=models.CASCADE)
    key = models.CharField(verbose_name="Google秘钥",max_length=128)
```



### #4.2 登陆


```
class loginView(APIView):
    def post(self,request):
        user = authenticate(username=request.data["username"], password=request.data["password"])
        if not user:
            raise Http404("账号密码不匹配")
        try:
            # 判断用户是否已经绑定Google令牌
            key = models.Google2Auth.objects.get(
                Q(user__username=request.data["username"])|Q(user__email=request.data["username"])).key
        except:
            raise Http404("未绑定令牌")
        if not Google_Verify_Result(key, request.data["code"]):
            # 验证令牌
            return Response({"success": True, "msg": "令牌失效", "results": None}, status=status.HTTP_400_BAD_REQUEST)
        login(request, user)
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        return Response({ "success": True, "msg": "登录成功","results": token},status=status.HTTP_200_OK)
```

## 总结

随机生成的字符串在客户端保存是通过二维码保存,在服务端保存在数据库中,用户在App上拿到的验证码是App中的算法经过随机字符串+时间戳+其他 生成的(这里的随机字符串和时间戳可以理解为盐),然后用户在登录时,经过服务端的算法时,把用户对应的字符串+验证码+本地时间戳,Google提供的算法会返回是否匹配

## App
- Google令牌+扫码器(如果手机只安装Google令牌App扫码失败,请安装扫码器)
链接：https://pan.baidu.com/s/1XeO7p4IvNuvzQOiZrq4wtw 
提取码：e70f 

- Chrome插件(不需要手机App,用插件就能绑定)

```
https://chrome.google.com/webstore/detail/authenticator/bhghoamapcdpbohphigoooaddinpkbai
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190109154621529.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0NveGh1YW5n,size_16,color_FFFFFF,t_70)
