# Generated by Django 2.2.6 on 2020-04-16 07:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('early_review', '0026_auto_20200414_1341'),
    ]

    operations = [
        migrations.AddField(
            model_name='authuser',
            name='usertype',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]