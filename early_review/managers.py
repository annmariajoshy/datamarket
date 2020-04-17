from django.db import models

from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)


class AuthUserManager(BaseUserManager):
    def create_user(self, email, password=None, user_name=None, *args, **kwargs):
        """
        Creates and saves a User with the given email,password.
        """
        random_string = kwargs.get('randomString', None)
        private = kwargs.get('private',None)
        public = kwargs.get('public', None)
        usertype = kwargs.get('usertype', None)

        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            user_name=user_name,
            random_string=random_string,
            private_key = private,
            public_key = public,
            usertype = usertype
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, user_name=None):
        """
        Creates and saves a superuser with the given email, password.
        """
        user = self.create_user(
            email,
            password=password,
            user_name=user_name
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class UserProductReviewAfterSpamQuerySet(models.QuerySet):

    def filter_by_query_params(self, request):
        items = self
        product_id_str = request.GET.get('product_id', None)

        if product_id_str:
            items = items.filter(product_id__iexact=product_id_str.strip())

        return items


class UserProductReviewBeforeSpamQuerySet(models.QuerySet):

    def filter_by_query_params(self, request):
        items = self
        product_id_str = request.GET.get('product_id', None)

        if product_id_str:
            items = items.filter(product_id__iexact=product_id_str.strip())

        return items
