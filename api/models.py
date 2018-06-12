from __future__ import unicode_literals

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _


# Create your models here.

class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, is_staff,
                     is_superuser, is_student, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if is_superuser:
            is_student = False
        now = timezone.now()
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, is_staff=is_staff,
                          is_student=is_student, is_active=True,
                          is_superuser=is_superuser, last_login=now,
                          date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        return self._create_user(email, password, False, False, True,
                                 **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True, False,
                                 **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """this class represents the user Model.
    """

    class Meta:
        db_table = 'users'
        managed = True

    username = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(max_length=254, unique=True)
    country_code = models.IntegerField(blank=True, null=True)
    contact_no = models.BigIntegerField(blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    is_password_changed = models.BooleanField(default=False)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin '
                                               'site.'))
    is_student = models.BooleanField(_('student status'), default=True,
                                     help_text=_('Designates whether the user can log into this admin '
                                                 'site.'))
    is_active = models.BooleanField(_('active'), default=True,
                                    help_text=_('Designates whether this user should be treated as '
                                                'active. Unselected this instead of deleting accounts.'))
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s' % self.username
        return full_name.strip()

    def get_short_name(self):
        """Returns the short name for the user."""
        return self.username

    def __unicode__(self):
        return self.email


class UserResetPassword(models.Model):
    class Meta:
        db_table = 'user_reset_password'

    user = models.OneToOneField(User)
    is_valid_key = models.BooleanField(default=False)
    key = models.CharField(max_length=40, blank=True)
    key_expires = models.DateTimeField()

    def __unicode__(self):
        return self.user

    def __repr__(self):
        return str(self.id)


class Course(models.Model):
    class Meta:
        db_table = 'courses'
        managed = True
    name = models.CharField(max_length=100, blank=True)
    description = models.TextField(max_length=5000, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    is_available = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    student_count = models.IntegerField(default=0)
    max_student = models.IntegerField(default=5)

    def __unicode__(self):
        return self.name


class StudentCourse(models.Model):
    class Meta:
        db_table = 'student_course'
        unique_together = ("student", "course")
        managed = True

    student = models.ForeignKey(User)
    course = models.ForeignKey(Course)

    def __unicode__(self):
        return "%s - %s" % (self.student, self.course)

    def __repr__(self):
        return "%s - %s" % (self.student, self.course)
