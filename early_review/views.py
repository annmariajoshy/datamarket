import datetime
import random
import string
import io
import PyPDF2
import uuid
import pickle
# from paillier.paillier import *


from phe import paillier
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import os, random, struct
from Crypto.Cipher import AES
from django.contrib.auth import authenticate
from django.db import transaction
from rest_framework import viewsets, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

from .serializers import (UserProductReviewAfterSpamSerializer, AuthUserSerializer, JsonFileUploadSerializer,
                          UserProductReviewBeforeSpamSerializer, EncryptFileSerializer)
from .models import (UserProductReviewAfterSpam, AuthUser, JsonFileUpload, UserThreshold, UserProductReviewBeforeSpam)
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


# nltk.download('movie_reviews')
# nltk.download(' product_reviews_1')
# nltk.download('product_reviews_1')


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


class UserProductReviewAfterSpamViewSet(viewsets.ModelViewSet, FullListAPI):
    queryset = UserProductReviewAfterSpam.objects.all()
    serializer_class = UserProductReviewAfterSpamSerializer

    # filter_fields = ['product_id']

    def list(self, request):
        self.queryset = self.queryset.filter_by_query_params(request)
        return super(UserProductReviewAfterSpamViewSet, self).list(request)

    @list_route()
    def early(self, request):
        product_id = request.GET.get('product_id', None)
        if not product_id:
            return Response(['Please Send product_id as query string.'])
        try:
            product_review = UserProductReviewAfterSpam.objects.filter(product_id=product_id)
            first_date = product_review.order_by('date_review').first().date_review
            last_date = product_review.order_by('date_review').last().date_review
            difference = (last_date - first_date) / 3
            second_date = first_date + datetime.timedelta(days=difference.days)
            output_data = product_review.filter(date_review__gte=first_date,
                                                date_review__lte=second_date)
        except UserProductReviewAfterSpam.DoesNotExist:
            return Response(['Please send valid new product_id.'])
        early_rating_tot = 0
        lst_data = []
        for row in output_data:
            dct_data = {}
            dct_data['id'] = row.id
            dct_data['product_id'] = row.product_id
            dct_data['product_name'] = row.product_name
            dct_data['reviewer_id'] = row.reviewer_id
            dct_data['reviewer_name'] = row.reviewer_name
            dct_data['review_text'] = row.review_text
            dct_data['overall_rating'] = row.overall_rating
            early_rating_tot += row.overall_rating
            dct_data['summary_product'] = row.summary_product
            dct_data['timestamp_review'] = row.timestamp_review
            dct_data['date_review'] = row.date_review
            lst_data.append(dct_data)
        rating_avg = early_rating_tot / len(output_data)
        early_count = len(output_data)
        data = {'rating_avg': rating_avg, 'early_count': early_count, 'data': lst_data}
        return Response(data)

    @list_route()
    def middle(self, request):
        product_id = request.GET.get('product_id', None)
        if not product_id:
            return Response(['Please Send product_id as query string.'])
        try:
            product_review = UserProductReviewAfterSpam.objects.filter(product_id=product_id)
            first_date = product_review.order_by('date_review').first().date_review
            last_date = product_review.order_by('date_review').last().date_review
            difference = (last_date - first_date) / 3
            second_date = first_date + datetime.timedelta(days=difference.days)
            third_date = second_date + datetime.timedelta(days=difference.days)
            output_data = product_review.filter(date_review__gt=second_date,
                                                date_review__lte=third_date)
        except UserProductReviewAfterSpam.DoesNotExist:
            return Response(['Please send valid new product_id.'])
        middle_rating_tot = 0
        lst_data = []
        for row in output_data:
            dct_data = {}
            dct_data['id'] = row.id
            dct_data['product_id'] = row.product_id
            dct_data['product_name'] = row.product_name
            dct_data['reviewer_id'] = row.reviewer_id
            dct_data['reviewer_name'] = row.reviewer_name
            dct_data['review_text'] = row.review_text
            dct_data['overall_rating'] = row.overall_rating
            middle_rating_tot += row.overall_rating
            dct_data['summary_product'] = row.summary_product
            dct_data['timestamp_review'] = row.timestamp_review
            dct_data['date_review'] = row.date_review
            lst_data.append(dct_data)
        rating_avg = middle_rating_tot / len(output_data)
        middle_count = len(output_data)
        data = {'rating_avg': rating_avg, 'middle_count': middle_count, 'data': lst_data}

        return Response(data)

    @list_route()
    def laggard(self, request):
        product_id = request.GET.get('product_id', None)
        if not product_id:
            return Response(['Please Send product_id as query string.'])
        try:
            product_review = UserProductReviewAfterSpam.objects.filter(product_id=product_id)
            first_date = product_review.order_by('date_review').first().date_review
            last_date = product_review.order_by('date_review').last().date_review
            difference = (last_date - first_date) / 3
            second_date = first_date + datetime.timedelta(days=difference.days)
            third_date = second_date + datetime.timedelta(days=difference.days)
            fourth_date = third_date + datetime.timedelta(days=difference.days)
            output_data = product_review.filter(date_review__gt=third_date,
                                                date_review__lte=fourth_date)
        except UserProductReviewAfterSpam.DoesNotExist:
            return Response(['Please send valid new product_id.'])
        laggard_rating_tot = 0
        lst_data = []
        for row in output_data:
            dct_data = {}
            dct_data['id'] = row.id
            dct_data['product_id'] = row.product_id
            dct_data['product_name'] = row.product_name
            dct_data['reviewer_id'] = row.reviewer_id
            dct_data['reviewer_name'] = row.reviewer_name
            dct_data['review_text'] = row.review_text
            dct_data['overall_rating'] = row.overall_rating
            laggard_rating_tot += row.overall_rating
            dct_data['summary_product'] = row.summary_product
            dct_data['timestamp_review'] = row.timestamp_review
            dct_data['date_review'] = row.date_review
            lst_data.append(dct_data)
        rating_avg = laggard_rating_tot / len(output_data)
        laggard_count = len(output_data)
        data = {'rating_avg': rating_avg, 'laggard_count': laggard_count, 'data': lst_data}

        return Response(data)

    @list_route()
    def sentimental_analysis(self, request):
        pos = 0
        neg = 0
        product_id = request.GET.get('product_id', None)
        if not product_id:
            return Response(['Please Send product_id as query string.'])
        try:
            product_review = UserProductReviewAfterSpam.objects.filter(product_id=product_id)
            first_date = product_review.order_by('date_review').first().date_review
            last_date = product_review.order_by('date_review').last().date_review
            difference = (last_date - first_date) / 3
            second_date = first_date + datetime.timedelta(days=difference.days)
            output_data = product_review.filter(date_review__gte=first_date,
                                                date_review__lte=second_date)
        except UserProductReviewAfterSpam.DoesNotExist:
            return Response(['Please send valid new product_id.'])

        def extract_features(word_list):
            return dict([(word, True) for word in word_list])

        def sentimental_output(review_text, co, pos, neg):
            # print("TXT", review_text.split('.'))
            split_text = review_text.split('.')
            if co == 1:
                # print("if-COUNT", co)
                positive_fileids = movie_reviews.fileids('pos')
                negative_fileids = movie_reviews.fileids('neg')
                features_positive = [(extract_features(movie_reviews.words(fileids=[f])), 'Positive') for f in
                                     positive_fileids]
                features_negative = [(extract_features(movie_reviews.words(fileids=[f])), 'Negative') for f in
                                     negative_fileids]
                threshold_factor = 0.8
                threshold_positive = int(threshold_factor * len(features_positive))
                threshold_negative = int(threshold_factor * len(features_negative))
                features_train = features_positive[:threshold_positive] + features_negative[:threshold_negative]
                features_test = features_positive[threshold_positive:] + features_negative[threshold_negative:]

                self.classifier = NaiveBayesClassifier.train(features_train)
            pred_sentiment_lst = []
            pred_sentiment_sum = 0
            for text in split_text:
                probdist = self.classifier.prob_classify(extract_features(text.split()))
                # print("PROB_DIST", vars(probdist))
                pred_sentiment = probdist.max()
                text_probability = round(probdist.prob(pred_sentiment), 2)
                pred_sentiment_sum += text_probability
                pred_sentiment_lst.append(pred_sentiment)
            # print("SENTI", pred_sentiment)
            positive_counter = 0
            negative_counter = 0
            print("LST", pred_sentiment_lst)
            for i in range(0, len(pred_sentiment_lst)):
                if pred_sentiment_lst[i] == 'Positive':
                    positive_counter += 1
                else:
                    negative_counter += 1
            print("counter", positive_counter)
            lst_data = []
            dct_data = {}
            dct_data['product_name'] = row.product_name
            dct_data['reviewer_name'] = row.reviewer_name
            dct_data['review_text'] = review_text
            # dct_data['predicted_sentiment'] = pred_sentiment
            dct_data['predicted_sentiment'] = "Positive" if positive_counter >= negative_counter else "Negative"

            if dct_data['predicted_sentiment'] == "Positive":
                pos += 1

            else:
                neg += 1
            # dct_data['Probability'] = round(probdist.prob(pred_sentiment), 2)
            dct_data['Probability'] = round(pred_sentiment_sum / len(pred_sentiment_lst), 2)
            lst_data.append(dct_data)

            return [lst_data, pos, neg]

        lst = []
        rtn = []
        tot_pos = 0
        tot_neg = 0
        co = 0
        for row in output_data:
            co += 1
            # print("USER", row.reviewer_name)
            rtn = sentimental_output(row.review_text, co, pos, neg)
            lst.extend(rtn[0])
            tot_pos += rtn[1]
            tot_neg += rtn[2]
        data = {'pos_count': tot_pos, 'neg_count': tot_neg, 'data': lst}
        return Response(data)


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
                public = key.publickey()
                public1 = public.exportKey('PEM')
                private = key.exportKey('PEM')
                app_user = AuthUser.objects.create_user(email, password, user_name, randomString=randomString,
                                                        private=private, public=public1)
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
        def extract_features(word_list):
            return dict([(word, True) for word in word_list])

        def sentimental_output():
            positive_fileids = movie_reviews.fileids('pos')
            negative_fileids = movie_reviews.fileids('neg')

            features_positive = [(extract_features(movie_reviews.words(fileids=[f])), 'Positive')
                                 for f in positive_fileids]
            features_negative = [(extract_features(movie_reviews.words(fileids=[f])), 'Negative')
                                 for f in negative_fileids]
            threshold_factor = 0.8

            threshold_positive = int(threshold_factor * len(features_positive))
            threshold_negative = int(threshold_factor * len(features_negative))
            features_train = features_positive[:threshold_positive] + features_negative[:threshold_negative]
            features_test = features_positive[threshold_positive:] + features_negative[threshold_negative:]

            self.classifier = NaiveBayesClassifier.train(features_train)

        # @staticmethod
        def sentimental_probdist(review_text):
            probdist = self.classifier.prob_classify(extract_features(review_text.split()))
            # print("prob_dist>>>>", probdist)

            pred_sentiment = probdist.max()

            return pred_sentiment

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

                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += ' ' * (16 - len(chunk) % 16)

                        outfile.write(encryptor.encrypt(chunk))
            return out_filename

        def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
            """ Decrypts a file using AES (CBC mode) with the
                given key. Parameters are similar to encrypt_file,
                with one difference: out_filename, if not supplied
                will be in_filename without its last extension
                (i.e. if in_filename is 'aaa.zip.enc' then
                out_filename will be 'aaa.zip')
            """
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


class UserProductReviewBeforeSpamViewSet(viewsets.ModelViewSet, FullListAPI):
    queryset = UserProductReviewBeforeSpam.objects.all()
    serializer_class = UserProductReviewBeforeSpamSerializer

    # filter_fields = ['product_id']

    def list(self, request):
        self.queryset = self.queryset.filter_by_query_params(request)
        return super(UserProductReviewBeforeSpamViewSet, self).list(request)


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
        pdfFileObj = request.data.get('file_upload', None)
        print("PDF", pdfFileObj)
        # pdfReader = PyPDF2.PdfFileReader(io.BytesIO(pdfFileObj))
        # pdfReader = pdfFileObj.name
        print('pdfreader', pdfFileObj)
        # NumPages = pdfReader.numPages
        i = 0
        password = 'hello'
        # file_name = "./" + str(uuid.uuid4()) + ".txt"

        # TODO: Uncmment
        # email = request.data['email']
        # product_review = AuthUser.objects.filter(email=email).first()
        # public = bytes(product_review.public_key, 'utf-8')
        # ====================================
        public1 = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWZkgcpaG3yHMa0Ru2y+wf8k7G\nBFTlav8Wwz49fyjlKQWc+k02kCVZeydV8LeeD3JDrBDN3eEebpvA8bmwt8izb1b/\nDn+DMGnKwJmO+Rtfzw697xiNR3pwm2BsiPT+69y+fuXqPzbMWXRWT5UF2jAkU72J\n15EXQ5vSY2b8pSA0TwIDAQAB\n-----END PUBLIC KEY-----'
        private = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDWZkgcpaG3yHMa0Ru2y+wf8k7GBFTlav8Wwz49fyjlKQWc+k02\nkCVZeydV8LeeD3JDrBDN3eEebpvA8bmwt8izb1b/Dn+DMGnKwJmO+Rtfzw697xiN\nR3pwm2BsiPT+69y+fuXqPzbMWXRWT5UF2jAkU72J15EXQ5vSY2b8pSA0TwIDAQAB\nAoGABqtCszJO25SD2BOXEzX/iJ9N5mwKg/8H6rbKByt0asDa6J8Cx5+ZyAo13j8K\nDjy0/God37JamNj1fqhiq/P/GAnZavz7VlMkW5H+AsPRFkw56kBwg+Wa+ZkZ05DX\nn2kvKqIFgJHDkvK1qVtM3bTqYneTxAgjmXkSYY5KHL2BspECQQDijEGixJo5lNOr\nEC3w2ydq+nO7mEmInB1T6hyJmx8WSo6D4vf+XE3NnqlaDM5/ovJcs3KmbNcygzZz\nXpr5No/JAkEA8kW3W1YID8Or38WItX+1AoFmYlDEdoXn8PuGJlOiJLJ00OzwB3zZ\nNOYzrrEDvX8VDwYQusffbRSKKSSlpMwfVwJBAJgyGbY71lBwx3LYv8RbtrOL5kxV\nFrGMD7fcQ6e+argTBoNb67caU7qbqLIygFgHJENa2t8rp7brp50CJaLfIOECQQDV\ni4nQogY9DvXiKdUUVdqQuMosApEI/4KvsKRQCAu1WO8KcK4pi2xQ6k/HvRNU5j0D\nnw8D88UF+sLE/R5cIefFAkB3gu/h1TVLpdXS5W2GaudiNsSl52gG8SjxnNhBH4lw\nGH9sBVYxkmROZTMBwL6nwoKuzu1sAJf3zLbALo/XP480\n-----END RSA PRIVATE KEY-----'
        rsa_publickey = RSA.importKey(public1)
        rsa_privatekey = RSA.importKey(private)
        print('importkey', rsa_publickey)
        cipher = PKCS1_OAEP.new(rsa_publickey)
        cipher1 = PKCS1_OAEP.new(rsa_privatekey)
        print('cipher', cipher)
        ciphertext = cipher.encrypt(b'hello')
        print('key encryped', ciphertext)
        plaintext = cipher1.decrypt(ciphertext)
        print('key decrypted', plaintext)
        out = self.encrypt_file(b'00112233445566778899aabbccddeeff', pdfFileObj)
        return Response({"message": "success"})

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
            out_filename = in_filename.name + '.enc'
            print('filename', out_filename)
        # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        iv = os.urandom(16)
        # iv = bytes(iv,'utf-8')
        print('eiv', iv)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        print('encryptor', encryptor)
        filesize = os.path.getsize(str(in_filename))
        print('filesize', filesize)
        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += ' ' * (16 - len(chunk) % 16)

                    outfile.write(encryptor.encrypt(chunk))
        return out_filename

    git config --
    global user.email
    "you@example.com"
    git
    config - -
    global user.name
    "Your Name"

