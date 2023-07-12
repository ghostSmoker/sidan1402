import jwt,datetime
from rest_framework import exceptions
import os
from Crypto.Cipher import AES
import binascii
import time 
import uuid
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import requests
import json
import random
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def create_access_token(id):
    return jwt.encode({
        'user_id':id,
        'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'iat':datetime.datetime.utcnow()

    },'access_secret',algorithm='HS256')

def decode_access_token(token):
    try:
        payload = jwt.decode(token,'access_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')

def create_refresh_token(id):
    return jwt.encode({
        'user_id' : id,
        'exp':datetime.datetime.utcnow() + datetime.timedelta(days=30),
        'iat':datetime.datetime.utcnow()
    },'refresh_secret',algorithm='HS256')

def decode_refresh_token(token):
    try:
        payload = jwt.decode(token,'refresh_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')

def remove_none_values(d):
    if isinstance(d, dict):
        return {k: remove_none_values(v) for k, v in d.items() if v is not None}
    return d

def create_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,
        backend=default_backend()
        )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_key_pem.decode('utf-8')
    private_key_str = private_key_str.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
    # print(private_key_str)

    with open("private_key.txt", "wb") as f:
        f.write(private_key_pem)

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_str = public_key_pem.decode('utf-8')
    public_key_str = public_key_str.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
    # print(public_key_str)

    with open("public_key.txt", "wb") as f:
        f.write(public_key_pem)

    return private_key_str, public_key_str


