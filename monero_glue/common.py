#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mnero import mininero
from monero_serialize import xmrtypes, xmrserialize, protobuf as xproto
import hashlib
import functools


def hash_bytearray(ba):
    """
    Hashing bytearrat
    :param ba:
    :return:
    """
    return functools.reduce(lambda a,d: (a*256 + d), ba, 0)


class HashWrapper(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def update(self, buf):
        if len(buf) == 0:
            return
        if isinstance(buf, bytearray):
            self.ctx.update(bytes(buf))  # TODO: optimize
        else:
            self.ctx.update(buf)

    def digest(self):
        return self.ctx.digest()

    def hexdigest(self):
        return self.ctx.hexdigest()


def get_keccak():
    """
    Simple keccak 256
    :return:
    """
    return hashlib.sha3_256()


def keccak_hash(inp):
    """
    Hashesh input in one call
    :return:
    """
    ctx = get_keccak()
    ctx.update(inp)
    return ctx.digest()


def get_keccak_writer(sub_writer=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :return:
    """
    return xproto.AHashWriter(HashWrapper(get_keccak()), sub_writer=sub_writer)



