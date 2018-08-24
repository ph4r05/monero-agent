#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from Crypto.Cipher import AES


def encrypt(key, plaintext, iv=None):
    """
    Uses AES-CBC for encryption
    :param key:
    :param plaintext:
    :param iv:
    :return: ciphertext
    """

    cipher = AES.new(key, AES.MODE_ECB, iv=iv)
    return cipher.encrypt(plaintext)


def decrypt(key, ciphertext, iv=None):
    """
    AES-CBC decryption
    :param key:
    :param ciphertext:
    :param iv:
    :return:
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(ciphertext)
