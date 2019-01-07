from django.shortcuts import render
from rest_framework.views import APIView
from app import models
from rest_framework.response import Response
from rest_framework import serializers
from drf_dynamic_fields import DynamicFieldsMixin
from django.contrib.auth import authenticate
from rest_framework_jwt.settings import api_settings
import base64
import codecs
import random
import re
import pyotp
from app import googletotp
from django.shortcuts import Http404
from django.db.models import Q
from rest_framework import status
from rest_framework.viewsets import GenericViewSet
from rest_framework import mixins
from django.contrib.auth import authenticate,login




"""2. 新增玩家"""
class UserSerializer(DynamicFieldsMixin,serializers.ModelSerializer):
    class Meta:
        model = models.UserProfile
        fields = ["username","password","email",]
    def create(self, validated_data):
        user= models.UserProfile.objects.create_user(**validated_data) # 这里新增玩家必须用create_user,否则密码不是秘文
        return user

class createUser(mixins.CreateModelMixin,GenericViewSet):
    queryset = models.UserProfile.objects.all()
    serializer_class = UserSerializer

"""绑定Google令牌"""
class googleSerializer(DynamicFieldsMixin,serializers.ModelSerializer):
    username = serializers.CharField()
    password = serializers.CharField()
    class Meta:
        model = models.UserProfile
        fields = ["username","password",]
    def validate_username(self, username):
        user = authenticate(username=username, password=self.initial_data["password"])
        if not user:
            raise Http404("账号密码不匹配")
        return username

class googleBindAPI(APIView):
    def post(self,request):
        queryset = models.Google2Auth.objects.filter(Q(user__username=request.data["username"]) | Q(user__email=request.data["username"]))
        if queryset.exists():
            raise Http404("已经绑定令牌,绑定失败")
        serializer = googleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = models.UserProfile.objects.get(Q(email=request.data["username"]) | Q(username=request.data["username"]))
        login(request, user)
        base_32_secret = base64.b32encode(codecs.decode(codecs.encode('{0:020x}'.format(random.getrandbits(80))), 'hex_codec'))
        totp_obj = googletotp.TOTP(base_32_secret.decode("utf-8")) # 实例化类
        qr_code = re.sub(r'=+$', '', totp_obj.provisioning_uri(request.user.email))
        models.Google2Auth.objects.create(user=user)
        key = str(base_32_secret,encoding="utf-8")
        queryset.update(key=key)
        return Response({"success": True, "msg": "绑定成功","results": {"qr_code": qr_code}}, status=status.HTTP_201_CREATED)


def Google_Verify_Result(secret_key,verifycode):
    t = pyotp.TOTP(secret_key)
    result = t.verify(verifycode) #对输入验证码进行校验，正确返回True
    res = result if result is True else False
    print("ret:",res)
    return res

class loginView(APIView):
    def post(self,request):
        print("ppp")
        user = authenticate(username=request.data["username"], password=request.data["password"])
        if not user:
            raise Http404("账号密码不匹配")
        try:
            # 判断用户是否已经绑定Google令牌
            key = models.Google2Auth.objects.get(
                Q(user__username=request.data["username"]) | Q(user__email=request.data["username"])).key
        except:
            raise Http404("未绑定令牌")
        print("oooo")
        if not Google_Verify_Result(key, request.data["code"]):
            # 验证令牌
            return Response({"success": True, "msg": "验证码失效", "results": None}, status=status.HTTP_400_BAD_REQUEST)
        login(request, user)
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        payload = jwt_payload_handler(user)
        token = jwt_encode_handler(payload)
        return Response({ "success": True, "msg": "登录成功","results": token},status=status.HTTP_200_OK)
