from django.db import models
from .managers import UserProductReviewAfterSpamQuerySet, AuthUserManager, UserProductReviewBeforeSpamQuerySet
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import ugettext_lazy as _



class AbstractTimeStampModel(models.Model):
    created_on = models.DateTimeField(auto_now_add=True, editable=False)
    updated_on = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class UserProductReviewAfterSpam(AbstractTimeStampModel):
    """
    Model to add  UserProductReview details.
    """
    product_id = models.CharField(max_length=128)
    product_name = models.CharField(max_length=128)
    reviewer_id = models.CharField(max_length=128)
    reviewer_name = models.CharField(max_length=128)
    review_text = models.CharField(max_length=10000)
    overall_rating = models.DecimalField(max_digits=11, decimal_places=4, null=True)
    summary_product = models.CharField(max_length=500)
    timestamp_review = models.IntegerField(default=0, null=True, blank=True)
    date_review = models.DateField()

    objects = UserProductReviewAfterSpamQuerySet.as_manager()

    def __str__(self):
        return self.product_id


class UserProductReviewBeforeSpam(AbstractTimeStampModel):
    """
    Model to add  UserProductReviewBeforeSpam details.
    """
    product_id = models.CharField(max_length=128)
    product_name = models.CharField(max_length=128)
    reviewer_id = models.CharField(max_length=128)
    reviewer_name = models.CharField(max_length=128)
    review_text = models.CharField(max_length=10000)
    overall_rating = models.DecimalField(max_digits=11, decimal_places=4, null=True)
    summary_product = models.CharField(max_length=500)
    timestamp_review = models.IntegerField(default=0, null=True, blank=True)
    date_review = models.DateField()

    objects = UserProductReviewBeforeSpamQuerySet.as_manager()

    def __str__(self):
        return self.product_id
#
# class BuyerUser(AbstractBaseUser, PermissionsMixin):
#     user = models.CharField(max_length=128, null=True, blank=True)

class AuthUser(AbstractBaseUser, PermissionsMixin):

    user_name = models.CharField(max_length=128, null=True, blank=True)
    email = models.EmailField(unique=True)
    random_string = models.CharField(max_length=256, null=True, blank=True)
    private_key = models.TextField(max_length=100000, null=True, blank= True)
    public_key = models.TextField(max_length=100000, null=True, blank=True)
    usertype = models.CharField(max_length=50, null=True, blank=True)
    is_staff = models.BooleanField(_('staff status'), default=False)

    objects = AuthUserManager()

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['email']

    def __str__(self):
        return str(self.email)

# class DataConsumer(AbstractBaseUser, PermissionsMixin):
#
#     buyer = models.charField(max_length=128, null=True, blank=True)
#     email = models.EmailField(unique=True)
class RegistrationCenter(AbstractTimeStampModel):

    center_name = models.CharField(max_length=128, null=True, blank=True)
    public_key = models.CharField(max_length=100000, null=True, blank=True)
    private_key = models.CharField(max_length=100000, null=True, blank= True)
    # is_staff = models.BooleanField(_('staff status'), default=False)

    # objects = RegistrationCenterManager()

    # USERNAME_FIELD = 'center_name'
    # REQUIRED_FIELDS = ['email']

    def __str__(self):
        return str(self.center_name)

class JsonFileUpload(AbstractTimeStampModel):

    file_upload = models.FileField(upload_to='json_files')

    def __str__(self):
        return self.file_upload.url

class EncryptionInfo(AbstractTimeStampModel):
    email = models.EmailField(null=False)
    file_title = models.CharField(max_length=1000)
    # encrypted_file = models.FileField(upload_to='encryption_files')
    encrypted_file_name = models.TextField(max_length=1000)
    secret_key_encrypted=models.TextField(max_length=128)

class SignedFile(AbstractTimeStampModel):
    email = models.EmailField(null=False)
    # file_title = models.CharField(max_length=1000)
    # encrypted_file = models.FileField(upload_to='encryption_files')
    encrypted_file_name = models.TextField(max_length=200)
    signed_file_name = models.TextField(max_length=200)
    checked = models.IntegerField(default=0, null=True, blank=True
                                  )
class UserThreshold(AbstractTimeStampModel):
    """
    Model to upload.
    """
    reviewer_id = models.CharField(max_length=128)
    reviewer_name = models.CharField(max_length=128)
    sentiment_threshold = models.IntegerField(default=0, null=True, blank=True)


    # objects = UserThresholdQuerySet.as_manager()

    def __str__(self):
        return self.reviewer_id



