from django.db import models
from django.contrib.auth.models import AbstractUser


class UserProfile(AbstractUser):
    """用户"""
    age = models.IntegerField(verbose_name="年龄",default=1)

class Google2Auth(models.Model):
    """GoogleAuth"""
    user = models.OneToOneField(UserProfile,on_delete=models.CASCADE)
    key = models.CharField(verbose_name="Google秘钥",max_length=128)




