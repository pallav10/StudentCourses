from django.conf.urls import url
from views import (UserRegistrationAPIView,
                   UserLoginAPIView,
                   UserLogoutAPIView,
                   ChangePasswordView)


urlpatterns = [
    url(r'^register/$', UserRegistrationAPIView.as_view(), name="list"),
    url(r'^login/$', UserLoginAPIView.as_view(), name="login"),
    url(r'^logout/$', UserLogoutAPIView.as_view(), name="logout"),
    url(r'^change_password/$', ChangePasswordView.as_view(), name="change_password"),
]