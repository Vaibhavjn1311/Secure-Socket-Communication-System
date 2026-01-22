import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
import random

class DESCrypto:
    PRIME = 23
    GENERATOR = 5

    @staticmethod
    def generate_private_key():
        return random.randint(1, DESCrypto.PRIME - 1)

    @staticmethod
    def compute_public_key(private_key):
        return pow(DESCrypto.GENERATOR, private_key, DESCrypto.PRIME)

    @staticmethod
    def compute_shared_key(private_key, other_public_key):
        shared_secret = pow(other_public_key, private_key, DESCrypto.PRIME)
        return hashlib.sha256(str(shared_secret).encode()).digest()[:14] 

    @staticmethod
    def generate_des_keys(shared_key):
        key1 = shared_key[:7]
        key2 = shared_key[7:]
        return key1, key2

    @staticmethod
    def simple_des_encrypt(data, key):
        return bytes([d ^ k for d, k in zip(data, key * (len(data) // len(key) + 1))])

    @staticmethod
    def simple_des_decrypt(data, key):
        return bytes([d ^ k for d, k in zip(data, key * (len(data) // len(key) + 1))])

    @staticmethod
    def double_des_encrypt(data, key1, key2):
        first_layer = DESCrypto.simple_des_encrypt(data, key1)
        return DESCrypto.simple_des_encrypt(first_layer, key2)

    @staticmethod
    def double_des_decrypt(data, key1, key2):
        first_layer = DESCrypto.simple_des_decrypt(data, key2)
        return DESCrypto.simple_des_decrypt(first_layer, key1)

    @staticmethod
    def generate_hmac(data, key):
        hmac = HMAC(key, hashes.SHA256())
        hmac.update(data)
        return hmac.finalize()

    @staticmethod
    def verify_hmac(data, key, signature):
        try:
            hmac = HMAC(key, hashes.SHA256())
            hmac.update(data)
            hmac.verify(signature)
            return True
        except:
            return False