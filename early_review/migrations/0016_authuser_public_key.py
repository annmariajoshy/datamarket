# Generated by Django 2.2.6 on 2020-02-09 11:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('early_review', '0015_auto_20191122_0508'),
    ]

    operations = [
        migrations.AddField(
            model_name='authuser',
            name='public_key',
            field=models.CharField(blank=True, max_length=100000, null=True),
        ),
    ]