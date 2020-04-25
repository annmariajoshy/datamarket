from django.conf import settings
from django.conf.urls import url, include
from django.conf.urls.static import static
from rest_framework import routers
from .views import  AuthUserViewSet, AuthUserModelViewSet, EncryptPdfFileViewSet, BatchVerificationViewSet, BatchListModelViewSet,FileListModelViewSet, FileDownloadModelViewSet

router = routers.SimpleRouter()
#router.register('user-product-early', UserProductReviewAfterSpamViewSet,
               # base_name='user-product-early')
router.register('registration', AuthUserViewSet,
                base_name='registration')
router.register('users', AuthUserModelViewSet,
                base_name='users')
# router.register('file-upload', FileUploadViewSet, base_name='file-upload')
router.register('file-upload', EncryptPdfFileViewSet, base_name='file-upload')
#router.register('user-product-before-spam', UserProductReviewBeforeSpamViewSet, base_name='user-product-before-spam')
router.register('verify', BatchVerificationViewSet, base_name='verify')
router.register('list-verify', BatchListModelViewSet, base_name='list-verify')
router.register('file-list', FileListModelViewSet, base_name='file-list')
router.register('file-download', FileDownloadModelViewSet, base_name='file-download')

urlpatterns = [
    url(r'^api/', include(router.urls)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
