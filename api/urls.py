from django.conf.urls import url
from views import (StudentRegistrationAPIView,
                   UserLoginAPIView,
                   UserLogoutAPIView,
                   ChangePasswordView, EnrollStudentView, ListCourses, DeleteCourseView)


urlpatterns = [
    url(r'^register/$', StudentRegistrationAPIView.as_view(), name="list"),
    url(r'^login/$', UserLoginAPIView.as_view(), name="login"),
    url(r'^logout/$', UserLogoutAPIView.as_view(), name="logout"),
    url(r'^change_password/$', ChangePasswordView.as_view(), name="change_password"),
    url(r'^courses/$', ListCourses.as_view(), name="courses"),
    url(r'^enroll_student/$', EnrollStudentView.as_view(), name="enroll_student"),
    url(r'^remove_courses/$', DeleteCourseView.as_view(), name="remove_courses"),
]