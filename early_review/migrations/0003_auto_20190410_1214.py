# Generated by Django 2.0 on 2019-04-10 12:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('early_review', '0002_authuser_is_staff'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authuser',
            name='user_name',
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
    ]