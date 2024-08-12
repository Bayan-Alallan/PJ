from django.db import models
from django.contrib.auth.models import User

class User_Info(models.Model):
      username=models.CharField(max_length=200)
      email=models.CharField(max_length=200,unique=True)
      id=models.CharField(max_length=100,primary_key=True)

      def __str__(self):
        return self.username
