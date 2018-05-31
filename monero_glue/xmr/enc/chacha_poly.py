#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


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
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext, b''


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




