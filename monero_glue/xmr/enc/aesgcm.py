#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from Crypto.Cipher import AES


def encrypt(key, plaintext, associated_data=None):
    """
    Uses AES-GCM for encryption
    :param key:
    :param plaintext:
    :param associated_data:
    :return: iv, ciphertext, tag
    """

    cipher = AES.new(key, AES.MODE_GCM)
    if associated_data:
        cipher.update(associated_data)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce

    return nonce, ciphertext, tag


def decrypt(key, iv, ciphertext, tag, associated_data=None):
    """
    AES-GCM decryption
    :param key:
    :param associated_data:
    :param iv:
    :param ciphertext:
    :param tag:
    :return:
    """
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.

    # Validate MAC and decrypt
    # If MAC validation fails, ValueError exception will be thrown
    cipher = AES.new(key, AES.MODE_GCM, iv)
    if associated_data:
        cipher.update(associated_data)

    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data


