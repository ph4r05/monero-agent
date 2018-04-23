#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from Crypto.Cipher import ChaCha20
import pycryptonight
from monero_glue.xmr import crypto


def generate_key(data):
    """
    Chacha key derivation used in Monero
    :param data:
    :return:
    """
    return pycryptonight.cn_slow_hash(data)


def encrypt_xmr(priv_key, plaintext, authenticated=True):
    """
    Monero-like authenticated encryption with Chacha20 and EC signature

    :param priv_key:
    :param plaintext:
    :param authenticated:
    :return:
    """
    key = generate_key(crypto.encodeint(priv_key))
    ciphertext = encrypt(key, plaintext)
    if not authenticated:
        return ciphertext

    hash = crypto.cn_fast_hash(ciphertext)
    c, r, pub = crypto.generate_signature(hash, priv_key)
    signature = crypto.encodeint(c) + crypto.encodeint(r)
    return ciphertext + signature


def decrypt_xmr(priv_key, ciphertext, authenticated=True):
    """
    Monero-like authenticated decryption with Chacha20 and EC signature

    :param priv_key:
    :param ciphertext:
    :param authenticated:
    :return:
    """
    if authenticated:
        ciphertext, signature = ciphertext[:-64], ciphertext[-64:]
        hash = crypto.cn_fast_hash(ciphertext)
        pub = crypto.scalarmult_base(priv_key)
        c = crypto.decodeint(signature[:32])
        r = crypto.decodeint(signature[32:])
        res = crypto.check_signature(hash, c, r, pub)
        if not res:
            raise ValueError('Signature invalid')

    key = generate_key(crypto.encodeint(priv_key))
    return decrypt(key, ciphertext)


def encrypt(key, plaintext):
    """
    Uses Chacha20 for encryption
    :param key:
    :param plaintext:
    :return: nonce+ciphertext
    """
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)

    nonce = cipher.nonce
    res = nonce + ciphertext
    return res


def decrypt(key, ciphertext):
    """
    Chacha20 decryption
    :param key:
    :param ciphertext:
    :return:
    """
    nonce, ciptext = ciphertext[:8], ciphertext[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciptext)


