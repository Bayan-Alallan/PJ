#from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, PasswordResetForm
from django.contrib import messages
from .forms import SignupForm, UpdateEmailForm
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from .serializers import UserSerializer
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.views import ObtainAuthToken
from django.core.mail import send_mail
from django.conf import settings



#signup
#This line declares a new class named SignupView, which inherits from APIView. The APIView class is part of Django REST Framework (DRF) and provides a base class for creating API views. It supports various HTTP methods and allows you to define how your API should respond to requests.
class SignupView(APIView):

#This line sets the permission_classes attribute to [AllowAny]. This means that this view will allow any user (authenticated or not) to access it
    permission_classes = [AllowAny]

#Here, an instance of UserSerializer is created with the incoming data from the request (request.data). The request.data contains the data sent by the client
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

# The Token.objects.get_or_create(user=user) method checks if a token already exists for the user. If it does, it retrieves it; if not, it creates a new token. The token is typically used for authenticating future requests from this user.
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







#login
class login_view(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key,},status=status.HTTP_200_OK)
    

#Logout
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    if request.method == 'POST':
        try:
            # Delete the user's token to logout
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        




#change_Password
class change_password(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if not user.check_password(current_password):
            return Response({"error": "Current password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"success": "Password updated successfully"}, status=status.HTTP_200_OK)
    


#forget_Password
class forget_password(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            # Generate password reset link logic here
            reset_link = "http://gmail.com/reset-password?uid={}".format(user.id)
            send_mail(
                'Password Reset Request',
                f'Click the link to reset your password: {reset_link}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            return Response({"success": "Password reset link sent to your email"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)
        



#update_email
class update_email(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        new_email = request.data.get('new_email')

        user.email = new_email
        user.save()
        return Response({"success": "Email updated successfully"}, status=status.HTTP_200_OK)
