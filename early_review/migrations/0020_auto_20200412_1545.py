# Generated by Django 2.2.6 on 2020-04-12 15:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('early_review', '0019_auto_20200412_1443'),
    ]

    operations = [
        migrations.AlterField(
            model_name='encryptioninfo',
            name='secret_key_encrypted',
            field=models.TextField(max_length=10000),
        ),
    ]
