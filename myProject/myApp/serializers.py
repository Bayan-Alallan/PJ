#this file descripe the transition phase from python to json
from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.authtoken.serializers import AuthTokenSerializer


#User Serializer
#declares a new class named UserSerializer. It inherits from serializers.ModelSerializer, which is a built-in serializer class provided by Django REST Framework (DRF). ModelSerializer is designed to create serializers that automatically handle the serialization and deserialization of Django model instances.
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)


#**Meta Class**: This line begins the declaration of an inner class called Meta. The Meta class is used to provide metadata options for the serializer. This includes information about the model that the serializer is associated with and which fields to include or exclude.
    class Meta:
        model = User
        fields = ['password', 'email', 'username']

#This line defines a method named create, which is overridden from the parent ModelSerializer. The purpose of this method is to handle the creation of a new user instance. It takes one argument, validated_data, which is a dictionary containing validated input data
    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user



#for login
class CustomAuthTokenSerializer(AuthTokenSerializer):
    def validate(self, attrs):
        # Perform any custom validation if necessary
        return super().validate(attrs)