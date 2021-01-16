from hashlib import pbkdf2_hmac
from os import urandom
from base64 import b64encode, b64decode
from time import sleep
from Crypto.Cipher import AES

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
    salt = salt.encode('utf-8')
    key = pbkdf2_hmac('sha256', password, salt, iterations=200000)
    return b64encode(key).decode('utf-8')

def encrypt_password(key, password):
    key = b64decode(key.encode('utf-8'))
    password = password.encode('utf-8')
    cipher = AES.new(key=key, mode=AES.MODE_EAX)

    encrypted, tag = cipher.encrypt_and_digest(password)
    encrypted = b64encode(encrypted).decode('utf-8')
    nonce = b64encode(cipher.nonce).decode('utf-8')
    tag = b64encode(tag).decode('utf-8')
    return encrypted, nonce, tag

def decrypt_password(key, encrypted_password, nonce, tag):
    key = b64decode(key.encode('utf-8'))
    encrypted = b64decode(encrypted_password.encode('utf-8'))
    nonce = b64decode(nonce.encode('utf-8'))
    tag = b64decode(tag.encode('utf-8'))
    cipher = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
    try:
        decrypted = cipher.decrypt_and_verify(encrypted, tag)
        decrypted = decrypted.decode('utf-8')
        return decrypted
    except Exception:
        raise Exception("Błędny master password")
