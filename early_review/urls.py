from django.conf import settings
from django.conf.urls import url, include
from django.conf.urls.static import static
from rest_framework import routers
from .views import  AuthUserViewSet, AuthUserModelViewSet, FileUploadViewSet, EncryptPdfFileViewSet

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

urlpatterns = [
    url(r'^api/', include(router.urls)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
