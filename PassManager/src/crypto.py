from hashlib import pbkdf2_hmac
from os import urandom
from base64 import b64encode, b64decode
from time import sleep
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

DELAY = 0.5

def hash_password(password):
    size = 64
    salt = urandom(size)
    password = password.encode('utf-8')
    h = pbkdf2_hmac('sha512', password, salt, 100000)
    salt = b64encode(salt).decode('utf-8')
    return h.hex(), salt

def verify_password(password, hash_pass, salt):
    sleep(DELAY)
    password = password.encode('utf-8')
    salt = b64decode(salt.encode('utf-8'))
    h = pbkdf2_hmac('sha512', password, salt, 100000).hex()
    return hash_pass == h

def create_key(password, salt):
    password = password.encode('utf-8')
    salt = b64decode(salt.encode('utf-8'))
    key = pbkdf2_hmac('sha256', password, salt, 200000)
    return key

def encrypt_password(key, password, nonce):
    password = password.encode('utf-8')
    nonce = nonce.encode('utf-8')
    cipher = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
    encrypted = cipher.encrypt(password)
    encrypted = b64encode(encrypted).decode('utf-8')
    return encrypted

def decrypt_password(key, encrypted_password, nonce):
    encrypted = b64decode(encrypted_password.encode('utf-8'))
    nonce = nonce.encode('utf-8')
    cipher = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt(encrypted)
    decrypted = decrypted.decode('utf-8')
    return decrypted
