from django.contrib import admin
from .models import UserProductReviewAfterSpam, AuthUser,JsonFileUpload,UserThreshold,UserProductReviewBeforeSpam,RegistrationCenter


admin.site.register(UserProductReviewAfterSpam)
admin.site.register(AuthUser)
admin.site.register(JsonFileUpload)
admin.site.register(UserThreshold)
admin.site.register(UserProductReviewBeforeSpam)
admin.site.register(RegistrationCenter)