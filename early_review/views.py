import datetime
import random
import string
import io
import PyPDF2
import uuid
import pickle
import time
# from paillier.paillier import *


from phe import paillier
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os, random, struct
from Crypto.Cipher import AES
from django.contrib.auth import authenticate
from django.db import transaction
from rest_framework import viewsets, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

from django.core.files import File

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

from .serializers import (UserProductReviewAfterSpamSerializer, AuthUserSerializer, JsonFileUploadSerializer,
                          UserProductReviewBeforeSpamSerializer, EncryptFileSerializer)
from .models import (UserProductReviewAfterSpam, AuthUser, JsonFileUpload, UserThreshold, UserProductReviewBeforeSpam,EncryptionInfo)
from rest_framework.decorators import detail_route, list_route, action

import nltk.classify.util
from nltk.classify import NaiveBayesClassifier
from nltk.corpus import movie_reviews
# from nltk.corpus import product_reviews_2
# import nltk
import pandas as pd

import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from django.shortcuts import render
from django.conf import settings
from django.core.files.storage import FileSystemStorage



class FullListAPI:
    """
    ?required_fields='id,code'
    """

    @list_route(methods=['GET'])
    def full_list(self, request):
        self.pagination_class = None
        fields = request.GET.get('fields')
        model = self.queryset.model
        try:
            select_related = self.select_related_fields
        except:
            select_related = ()
        try:
            prefetch_related = self.prefetch_related_fields
        except:
            prefetch_related = ()
        try:
            static_filters = self.static_filters
        except:
            static_filters = {}
        queryset = model.objects.select_related(
            *select_related).prefetch_related(
            *prefetch_related).filter_by_query_params(request)
        queryset = self.filter_queryset(queryset)
        if static_filters:
            queryset = queryset.filter(**static_filters)

        if fields:
            fields = tuple(f.strip() for f in fields.split(','))
            slz = self.serializer_class(queryset, many=True, fields=fields, context={'request': request})
        else:
            slz = self.serializer_class(queryset, many=True, context={'request': request})
        return Response(slz.data)

    @transaction.atomic
    @list_route(methods=['POST'])
    def bulk_upsert(self, request):
        """
        Insert or create multiple data at once
        """
        # TODO: check whether audit log is working or not
        if type(request.data) != list:
            raise Exception("Expected list for the bulk upsert")

        success_data = {
            'total_count': 0,
            'updated': 0,
            'inserted': 0
        }
        for item in request.data:
            id_ = item.get('id', None)
            if not id_:
                serializer = self.get_serializer(data=item)
                serializer.is_valid(raise_exception=True)
                self.perform_create(serializer)
                success_data['inserted'] += 1
            if id_:
                partial = True
                pk = int(id_)
                lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
                if pk:
                    self.kwargs['pk'] = pk
                instance = self.get_object()
                serializer = self.get_serializer(instance, data=item, partial=partial)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)
                success_data['updated'] += 1

        success_data['total_count'] = success_data['updated'] + success_data['inserted']
        return Response(success_data, status=status.HTTP_201_CREATED)


class AuthUserViewSet(viewsets.ViewSet):

    @action(methods=['POST'], detail=False)
    def login(self, request):
        print('login', request.data)

        email = request.data.get('email', None)
        password_str = request.data.get('password', None)

        email = email.strip()
        password = password_str.strip()
        print('random', email)

        if email and password:

            user = authenticate(email=email, password=password)
            print('user', user)
            if not user:
                return Response({'error': 'user not found'}, status=status.HTTP_404_NOT_FOUND)
            else:
                token = Token.objects.get_or_create(user=user)
                # private_key= UserProductReviewAfterSpam.objects.filter(email=email)
                return Response({'token': str(token[0]), 'message': 'login successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'provide email and password'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False)
    def register(self, request):
        print('request', request.data);
        email_str = request.data.get('email', None)
        # password_str = request.data.get('password', None)
        user_name_str = request.data.get('username', None)

        email = email_str.strip()
        # password = password_str.strip()
        user_name = user_name_str.strip()

        # if email and password and user_name:
        if email and user_name:
            try:
                user = AuthUser.objects.get_by_natural_key(email)
                return Response({'error': 'user already exist'}, status=status.HTTP_400_BAD_REQUEST)

            except AuthUser.DoesNotExist:
                lettersAndDigits = user_name + string.digits
                randomString = ''.join(random.choice(lettersAndDigits) for i in range(6))
                print('random string', randomString)
                password_characters = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(random.choice(password_characters) for i in range(5))
                print('password', password)
                random_generator = Random.new().read
                key = RSA.generate(1024)
                public = key.publickey().exportKey('PEM')
                public1 = public.decode()
                private = key.exportKey('PEM')
                private1 = private.decode()
                app_user = AuthUser.objects.create_user(email, password, user_name, randomString=randomString,
                                                        private=private1, public=public1)
                token = Token.objects.get_or_create(user=app_user)
                trying_email(user_name, randomString, password, email)
                return Response({'token': str(token[0]), 'message': 'registered successfully'},
                                status=status.HTTP_200_OK)

        else:
            return Response({'error': 'provide email and password'}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False)
    def changePassword(self, request):
        print('password', request.data)

        old_password = request.data.get('old_password', None)
        new_password = request.data.get('new_password', None)

        # old_password = old_password.strip()
        # new_password = new_password.strip()

        if old_password and new_password:
            user = authenticate(password=old_password)
            if not user:
                print('pswd not changd')
            else:
                print('pswd changed')


class AuthUserModelViewSet(viewsets.ModelViewSet, FullListAPI):
    queryset = AuthUser.objects.all()
    serializer_class = AuthUserSerializer

    def list(self, request):
        query_str = request.GET.get('query', None)

        if query_str:
            self.queryset = self.queryset.filter(username__icontains=query_str.strip())
        return super(AuthUserModelViewSet, self).list(request)


class FileUploadViewSet(viewsets.ModelViewSet, FullListAPI):
    serializer_class = JsonFileUploadSerializer
    queryset = JsonFileUpload.objects.all()

    @transaction.atomic
    def create(self, request):
        # def decrypt(enc, password):
        #     private_key = hashlib.sha256(password.encode("utf-8")).digest()
        #     enc = base64.b64decode(enc)
        #     iv = enc[:16]
        #     cipher = AES.new(private_key, AES.MODE_CBC, iv)
        #     return unpad(cipher.decrypt(enc[16:]))

        # def encrypt(raw, password):
        #     private_key = hashlib.sha256(password.encode("utf-8")).digest()
        #     raw = pad(raw)
        #     iv = Random.new().read(AES.block_size)
        #     cipher = AES.new(private_key, AES.MODE_CBC, iv)
        #     return base64.b64encode(iv + cipher.encrypt(raw))

        # pdfFileObj = request.FILES['file_upload']
        pdfFileObj = request.data.get('file_upload', None)
        print("PDF", pdfFileObj)
        # pdfReader = PyPDF2.PdfFileReader(io.BytesIO(pdfFileObj))
        #pdfReader = pdfFileObj.name
        print('pdfreader',pdfFileObj)
        # NumPages = pdfReader.numPages
        i = 0
        password = 'hello'
        # file_name = "./" + str(uuid.uuid4()) + ".txt"
        email = request.data['email']
        product_review = AuthUser.objects.filter(email=email).first()
        public = bytes(product_review.public_key, 'utf-8')
        public1 = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWZkgcpaG3yHMa0Ru2y+wf8k7G\nBFTlav8Wwz49fyjlKQWc+k02kCVZeydV8LeeD3JDrBDN3eEebpvA8bmwt8izb1b/\nDn+DMGnKwJmO+Rtfzw697xiNR3pwm2BsiPT+69y+fuXqPzbMWXRWT5UF2jAkU72J\n15EXQ5vSY2b8pSA0TwIDAQAB\n-----END PUBLIC KEY-----'
        private = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDWZkgcpaG3yHMa0Ru2y+wf8k7GBFTlav8Wwz49fyjlKQWc+k02\nkCVZeydV8LeeD3JDrBDN3eEebpvA8bmwt8izb1b/Dn+DMGnKwJmO+Rtfzw697xiN\nR3pwm2BsiPT+69y+fuXqPzbMWXRWT5UF2jAkU72J15EXQ5vSY2b8pSA0TwIDAQAB\nAoGABqtCszJO25SD2BOXEzX/iJ9N5mwKg/8H6rbKByt0asDa6J8Cx5+ZyAo13j8K\nDjy0/God37JamNj1fqhiq/P/GAnZavz7VlMkW5H+AsPRFkw56kBwg+Wa+ZkZ05DX\nn2kvKqIFgJHDkvK1qVtM3bTqYneTxAgjmXkSYY5KHL2BspECQQDijEGixJo5lNOr\nEC3w2ydq+nO7mEmInB1T6hyJmx8WSo6D4vf+XE3NnqlaDM5/ovJcs3KmbNcygzZz\nXpr5No/JAkEA8kW3W1YID8Or38WItX+1AoFmYlDEdoXn8PuGJlOiJLJ00OzwB3zZ\nNOYzrrEDvX8VDwYQusffbRSKKSSlpMwfVwJBAJgyGbY71lBwx3LYv8RbtrOL5kxV\nFrGMD7fcQ6e+argTBoNb67caU7qbqLIygFgHJENa2t8rp7brp50CJaLfIOECQQDV\ni4nQogY9DvXiKdUUVdqQuMosApEI/4KvsKRQCAu1WO8KcK4pi2xQ6k/HvRNU5j0D\nnw8D88UF+sLE/R5cIefFAkB3gu/h1TVLpdXS5W2GaudiNsSl52gG8SjxnNhBH4lw\nGH9sBVYxkmROZTMBwL6nwoKuzu1sAJf3zLbALo/XP480\n-----END RSA PRIVATE KEY-----'
        rsa_publickey = RSA.importKey(public1)
        rsa_privatekey = RSA.importKey(private)
        print('importkey', rsa_publickey)
        cipher = PKCS1_OAEP.new(rsa_publickey)
        cipher1 = PKCS1_OAEP.new(rsa_privatekey )
        print('cipher', cipher)
        ciphertext = cipher.encrypt(b'hello')
        print('key encryped', ciphertext)
        plaintext = cipher1.decrypt(ciphertext)
        print('key decrypted', plaintext)
        # BLOCK_SIZE = 16
        # pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE),
        #                       'utf-8')
        # unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        # with open(file_name, 'w') as open_file:
        #     while (i < NumPages):
        #         text = pdfReader.getPage(i)
        #         # content.append(text.extractText())
        #         i += 1
        #         encrypted = encrypt(text.extractText(), password)
        #         decrypted = decrypt(encrypted, password)
        #         open_file.write(str(encrypted) + '\n')
        #         open_file.write(str(decrypted) + '\n')
        #    # print('encrypted', text)

        def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
            if not out_filename:
                out_filename = in_filename.name + '.enc'
                print('filename', out_filename)
           # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
            iv = os.urandom(16)
            #iv = bytes(iv,'utf-8')
            print('eiv', iv)
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            print('encryptor', encryptor)
            filesize = os.path.getsize(str(in_filename))
            print('filesize', filesize)
            with open(in_filename, 'rb') as infile:
                with open(out_filename, 'wb') as outfile:
                    outfile.write(struct.pack('<Q', filesize))
                    outfile.write(iv)
                    print('helloooo')

                    while True:
                        chunk = infile.read(chunksize)
                        print('chunk',chunk)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += ' ' * (16 - len(chunk) % 16)

                        outfile.write(encryptor.encrypt(chunk))
            return out_filename

        def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
            if not out_filename:
                out_filename = os.path.splitext(in_filename)[0]

            with open(in_filename, 'rb') as infile:
                origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
                iv = infile.read(16)
                decryptor = AES.new(key, AES.MODE_CBC, iv)

                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))

                    outfile.truncate(origsize)

        out = encrypt_file(b'00112233445566778899aabbccddeeff', pdfFileObj)
        #decrypt_file(b'00112233445566778899aabbccddeeff', out)

        return Response({"message": "success", "data": encrypted})

        # except Exception as err:
        # return Response('error: {}'.format(str(err)))
        # except Exception as err:
        # return Response(['Please upload proper file', str(err)])


#
def trying_email(usr_name, user, pswd, email):
    sender = 'annmariajoshy77@gmail.com'
    password = 'godmystrength111'
    receivers = email
    print('maillllll')
    message = MIMEMultipart("alternative")
    message["Subject"] = "Username & Password"
    message["From"] = sender
    message["To"] = receivers
    context = ssl.create_default_context()
    text = "Hi {},\n \n Please find the login details \n Username: {}\n Password: {}\n".format(usr_name, email, pswd)

    part1 = MIMEText(text, "plain")
    message.attach(part1)
    print('text')
    try:
        print('tttttt')
        smtpObj = smtplib.SMTP("smtp.gmail.com", 587)
        smtpObj.starttls(context=context)  # Secure the connection
        smtpObj.login(sender, password)
        smtpObj.sendmail(sender, receivers, message.as_string())
        print("Successfully sent from:-->{}\n email to--->{}".format(sender, receivers))
    except smtplib.SMTPException as err:
        print(str(err))

# def trying_email(usr_name,user,pswd,email):
#     sender = 'annmariajoshy77@gmail.com'
#     password = 'godmystrength111'
#     receivers = email
#     print('maillllll')
#     # message = MIMEMultipart("alternative")
#     # message["Subject"] = "Username & Password"
#     # message["From"] = sender
#     # message["To"] = receivers
#     context = ssl.create_default_context()
#     server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
#     server.login("annmariajoshy77@gmail.com", "godmystrength111")
#     server.sendmail(
#         "annmariajoshy77@gmail.com",
#         "{}".format(receivers),
#         "Hi {},\n \n Please find the login details \n Email: {}\n Password: {}\n".format(usr_name,email, pswd))
#     server.quit()



class EncryptPdfFileViewSet(viewsets.ViewSet):
    serializer_class = EncryptFileSerializer

    @transaction.atomic
    def create(self, request):
        result = self.simple_upload(request)
        print('file_result',result)


        # TODO: Uncmment
        email = request.data['email']
        product_review = AuthUser.objects.filter(email=email).first()
        public = product_review.public_key
        private = product_review.private_key
        rsa_publickey = RSA.importKey(public.encode('utf-8'))
        rsa_privatekey = RSA.importKey(private.encode('utf-8'))

        lettersAndDigits = string.ascii_letters + string.digits
        randomString = "".join(random.choice(lettersAndDigits) for i in range(32))
        result_random= randomString.encode('utf-8')
        print('generated secret key',result_random)
        secret_encrypted = self.encrypt_secret(result_random,rsa_publickey)
        secret_decrypted = self.decrypt_secret(secret_encrypted,rsa_privatekey )
        print('encrypted secret key',secret_encrypted)
        
        print('decrypted secret key', secret_decrypted)

        out = self.encrypt_file(result_random, result)
        EncryptionInfo.objects.create(email=email,file_title='hello',encrypted_file=File(open(out)),secret_key_encrypted=secret_encrypted.decode())
        #self.decrypt_file(result_random, out)
        #self.sign(private,out)
        return Response({"message": "success"})

    def sign(self,private_key,enc_file):
        print('signnnnnnn')
        sign_private_key = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend(),)
        print('ppp', sign_private_key)

        file_path = os.path.abspath(os.path.join(enc_file))
        with open(file_path, 'rb') as f:
            payload = f.read()
        # Sign the payload file.
        signature = base64.b64encode(
            sign_private_key.sign(
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        )
        sign_file= os.path.splitext(enc_file)
        print('laaa',sign_file)
        signed_file = sign_file[0] +'.sig'
        with open(signed_file, 'wb') as f:
            f.write(signature)
        JsonFileUpload.objects.create(file_upload=File(open(signed_file)))
        #return signed_file







    def encrypt_file(self, key, in_filename, out_filename=None, chunksize=64 * 1024):
        """ Encrypts a file using AES (CBC mode) with the
            given key.

            key:
                The encryption key - a string that must be
                either 16, 24 or 32 bytes long. Longer keys
                are more secure.

            in_filename:
                Name of the input file

            out_filename:
                If None, '<in_filename>.enc' will be used.

            chunksize:
                Sets the size of the chunk which the function
                uses to read and encrypt the file. Larger chunk
                sizes can be faster for some files and machines.
                chunksize must be divisible by 16.
        """
        if not out_filename:
            out_filename = in_filename + '.enc'
            print('filename', out_filename)
        # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        iv = os.urandom(16)
        # iv = bytes(iv,'utf-8')
        print('eiv', iv)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        print('encryptor', encryptor)
        hello =  os.path.abspath(os.path.join('media', in_filename))
        print('helllllo',hello)
        filesize = os.path.getsize(hello)
        print('filesize', filesize)
        with open(hello, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk1 = b' ' * (16 - len(chunk) % 16)
                        print('hellloo',type(chunk1))
                        chunk += chunk1

                    outfile.write(encryptor.encrypt(chunk))
        return out_filename


    def decrypt_file(self,key, in_filename, out_filename=None, chunksize=24 * 1024):
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]
        hello = os.path.abspath(os.path.join(in_filename))
        with open(hello, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)

            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))

                outfile.truncate(origsize)

    def simple_upload(self,request):
        if request.method == 'POST' and request.FILES['file_upload']:
            myfile = request.FILES['file_upload']
            print('myfileee',myfile.name)
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            return filename

    def encrypt_secret(self,secret,public_key):
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(secret)
        print('TYPE OF SECRET KEY',type(ciphertext))
        return ciphertext
    def decrypt_secret(self,cipher_secret,private_key):
        cipher1 = PKCS1_OAEP.new(private_key)
        plaintext = cipher1.decrypt(cipher_secret)
        return plaintext


