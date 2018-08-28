#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    ChaCha20Poly1305(b"\x00" * 32)  # test if openssl provides ChaCha20Poly1305

except:
    from chacha20poly1305 import ChaCha20Poly1305


def encrypt(key, plaintext, associated_data=None):
    """
    Uses ChaCha20Poly1305 for encryption
    :param key:
    :param plaintext:
    :param associated_data:
    :return: iv, ciphertext, tag
    """
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(bytes(nonce), bytes(plaintext), associated_data)
    return nonce, ciphertext, b""


def decrypt(key, iv, ciphertext, tag=None, associated_data=None):
    """
    ChaCha20Poly1305 decryption
    :param key:
    :param iv:
    :param ciphertext:
    :param tag:
    :param associated_data:
    :return:
    """
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(iv, ciphertext, associated_data)
    return plaintext


def encrypt_pack(key, plaintext, associated_data=None):
    return b"".join(encrypt(key, plaintext, associated_data))


def decrypt_pack(key, ciphertext):
    return decrypt(key, ciphertext[:12], ciphertext[12:], None)
