from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings

from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken

from .serializers import UserSerializer
from rest_framework import viewsets


class UserViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        queryset = User.objects.all()
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data)





#signup

#This line declares a new class named SignupView, which inherits from APIView. The APIView class is part of Django REST Framework (DRF) and provides a base class for creating API views. It supports various HTTP methods and allows you to define how your API should respond to requests.
class signup_view(APIView):

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

#login_view that inherits from ObtainAuthToken. This means it will have all the functionalities of ObtainAuthToken, which is a built-in view for obtaining an authentication token.
class login_view(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})

#validates the data passed to the serializer. If the data is invalid, it raises an exception (typically a ValidationError), which will automatically return an error response to the client with details about what went wrong.
        serializer.is_valid(raise_exception=True)

#This assumes that the serializer has been set up to authenticate the user and include the authenticated user in its validated data.
        user = serializer.validated_data['user']

#to get an existing authentication token for the authenticated user. If no token exists, it creates a new one. The get_or_create method returns a tuple: the first element is the token object, and the second element (created) is a boolean indicating whether a new token was created or an existing one was retrieved.
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

#The permission_classes attribute specifies that only authenticated users can access this view. This is enforced by the IsAuthenticated permission class. If a user is not authenticated, they will receive a 403 Forbidden response.
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

#The check_password method of the user model is used to verify if the provided current password matches the user's existing password. If it does not match, a response with a 400 Bad Request status is returned, along with an error message.

        if not user.check_password(current_password):
            return Response({"error": "Current password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)
        
#If the current password is correct, the set_password method is called with the new password. This method not only sets the new password but also hashes it (for security) before saving it to the database.
        user.set_password(new_password)
        user.save()
        return Response({"success": "Password updated successfully"}, status=status.HTTP_200_OK)
    


#forget_Password
import logging

logger = logging.getLogger(__name__)

class forget_password(APIView):
    # Allow any user (authenticated or not) to access this view
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        logger.info(f"Received password reset request for email: {email}")

        try:
            user = User.objects.get(email=email)
            # Generate password reset link logic here
            reset_link = "http://localhost:3000/forget_password?uid={}".format(user.id)
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


