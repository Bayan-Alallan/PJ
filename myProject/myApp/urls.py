from django.urls import path
from . import views
from rest_framework.authtoken.views import ObtainAuthToken

urlpatterns = [
    path('signup/', views.signup_view.as_view(), name='signup'),
    path('login/', views.login_view.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('change_password/', views.change_password.as_view(), name='change_password'),
    path('forget_password/', views.forget_password.as_view(), name='forget_password'),
    path('update_email/', views.update_email.as_view(), name='update_email'),
    path('api-token-auth/', ObtainAuthToken.as_view(), name='api_token_auth'),
]

