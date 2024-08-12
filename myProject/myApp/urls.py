from django.urls import path,include
from . import views
from rest_framework.authtoken.views import ObtainAuthToken
from django.urls import path
#from .views import signup_view, login_view, logout_view, change_password, forget_password, update_email
from rest_framework.routers import DefaultRouter
from .views import UserViewSet



router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')



urlpatterns = [
    path('signup/', views.signup_view.as_view(), name='signup'),
    path('login/', views.login_view.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('change_password/', views.change_password.as_view(), name='change_password'),
    path('forget_password/', views.forget_password.as_view(), name='forget_password'),
    path('reset_password/', views.ResetPasswordView.as_view(), name='reset_password'),

    path('update_email/', views.update_email.as_view(), name='update_email'),
    path('api-token-auth/', ObtainAuthToken.as_view(), name='api_token_auth'),
    path('', include(router.urls)),


]

