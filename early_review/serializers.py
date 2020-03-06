from rest_framework import serializers
from .models import (UserProductReviewAfterSpam, AuthUser, JsonFileUpload,  UserProductReviewBeforeSpam)


class DynamicFieldsModelSerializer(serializers.ModelSerializer):
    """
    A ModelSerializer that takes an additional `fields` argument that
    controls which fields should be displayed.
    """

    def __init__(self, *args, **kwargs):
        # Don't pass the 'fields' arg up to the superclass
        fields = kwargs.pop('fields', None)
        exclude_fields = kwargs.pop('exclude_fields', None)
        if fields and exclude_fields:
            raise Exception("cannot use field and exclude fields together")

        # Instantiate the superclass normally
        super(DynamicFieldsModelSerializer, self).__init__(*args, **kwargs)

        # model_attributes = self.Meta.model.__dict__
        # exclude_properties = getattr(self.Meta, 'exclude_properties', [])
        # for attr_name, attr_val in model_attributes.items():
        #     if not isinstance(attr_val, (property,)):
        #         continue
        #     if attr_name not in self.fields and attr_name not in exclude_properties:
        #         self.fields[attr_name] = serializers.ReadOnlyField()

        if fields is not None:
            # Drop any fields that are not specified in the `fields` argument.
            allowed = set(fields)
            existing = set(self.fields.keys())
            for field_name in existing - allowed:
                self.fields.pop(field_name)

        if exclude_fields is not None:
            # Drop specific fields
            exclude = set(exclude_fields)
            for field_name in exclude:
                self.fields.pop(field_name)


class UserProductReviewAfterSpamSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserProductReviewAfterSpam
        # fields = [f.name for f in model._meta.fields]
        fields = '__all__'


class AuthUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuthUser
        # fields = [f.name for f in model._meta.fields]
        exclude = ['password', 'is_staff', 'groups', 'user_permissions']


class JsonFileUploadSerializer(DynamicFieldsModelSerializer):
    class Meta:
        model = JsonFileUpload
        fields = [f.name for f in model._meta.fields]


class UserProductReviewBeforeSpamSerializer(serializers.ModelSerializer):

    class Meta:
        model =  UserProductReviewBeforeSpam
        # fields = [f.name for f in model._meta.fields]
        fields = '__all__'


class EncryptFileSerializer(serializers.Serializer):
    file_upload = serializers.FileField()

    class Meta:
        fields = 'file_upload'