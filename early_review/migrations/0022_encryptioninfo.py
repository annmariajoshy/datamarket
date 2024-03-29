# Generated by Django 2.2.6 on 2020-04-14 12:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('early_review', '0021_delete_encryptioninfo'),
    ]

    operations = [
        migrations.CreateModel(
            name='EncryptionInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('updated_on', models.DateTimeField(auto_now=True)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('file_title', models.CharField(max_length=1000)),
                ('encrypted_file_name', models.TextField(max_length=1000)),
                ('secret_key_encrypted', models.TextField(max_length=10000)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
