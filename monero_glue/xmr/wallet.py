#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import json
import re

from monero_glue.xmr import crypto
from monero_glue.xmr.enc import chacha
from monero_serialize import xmrboost, xmrtypes, xmrserialize, xmrrpc

UNSIGNED_TX_PREFIX = b"Monero unsigned tx set\004"
SIGNED_TX_PREFIX = b"Monero signed tx set\004"
MULTISIG_UNSIGNED_TX_PREFIX = b"Monero multisig unsigned tx set\001"


def unescape_json_str(st):
    """
    Unescape Monero json encoded string

    :param st:
    :return:
    """
    c = 0
    ln = len(st)
    escape_chmap = {
        b'b': b'\b',
        b'f': b'\f',
        b'n': b'\n',
        b'r': b'\r',
        b't': b'\t',
        b'\\': b'\\',
        b'"': b'\"',
        b'/': b'\/'
    }

    ret = []

    def at(i):
        return st[i:i+1]

    while c < ln:
        if at(c) == b'\\':
            if at(c+1) == b'u':
                ret.append(bytes([int(st[c+2:c+6], 16)]))
                # ret.append(st[c:c+6].decode('unicode_escape').encode('utf8'))
                c += 6

            else:
                ret.append(escape_chmap[at(c+1)])
                c += 2

        else:
            ret.append(at(c))
            c += 1

    df = (b''.join(ret))
    return df


async def load_keys_file(file, password):
    """
    Loads wallet keys file
    :param file:
    :param password:
    :return:
    """
    with open(file, 'rb') as fh:
        data = fh.read()

    reader = xmrserialize.MemoryReaderWriter(bytearray(data))
    ar = xmrserialize.Archive(reader, False)
    msg = xmrtypes.KeysFileData()
    await ar.message(msg)

    key = chacha.generate_key(password)
    buff = bytes(msg.iv + msg.account_data)
    dec = chacha.decrypt(key, buff)

    m = re.search(b'(.*)"key_data":"(.+?)",?(.*)', dec)
    key_data = m.group(2)
    dat = unescape_json_str(key_data)

    reader = xmrserialize.MemoryReaderWriter(bytearray(dat))
    ar = xmrrpc.Archive(reader, False)

    key_data = {}
    await ar.root()
    await ar.section(key_data)

    rest_json = m.group(1) + m.group(3)
    wallet_key = json.loads(rest_json)
    wallet_key['key_data'] = key_data
    return wallet_key


async def load_unsigned_tx(priv_key, data):
    """
    Loads unsigned transaction from the encrypted file
    :param priv_key:
    :param data:
    :return:
    """
    magic_len = len(UNSIGNED_TX_PREFIX)
    magic = data[:magic_len - 1]
    version = int(data[magic_len - 1])
    data = data[magic_len:]

    if magic != UNSIGNED_TX_PREFIX[:-1]:
        raise ValueError('Invalid file header')
    if version != 4:
        raise ValueError('Unsigned transaction v4 is supported only')

    tx_uns_ser = chacha.decrypt_xmr(priv_key, data, authenticated=True)
    reader = xmrserialize.MemoryReaderWriter(bytearray(tx_uns_ser))
    ar = xmrboost.Archive(reader, False)

    msg = xmrtypes.UnsignedTxSet()
    await ar.root()
    await ar.message(msg)
    return msg


async def dump_signed_tx(priv_key, signed_tx):
    """
    Dumps signed_tx to a file as wallet produces

    :param priv_key:
    :param signed_tx:
    :return:
    """
    writer = xmrserialize.MemoryReaderWriter()
    ar = xmrboost.Archive(writer, True)
    await ar.root()
    await ar.message(signed_tx)

    ciphertext = chacha.encrypt_xmr(priv_key, bytes(writer.buffer), authenticated=True)
    return SIGNED_TX_PREFIX + ciphertext


def construct_pending_tsx(tx, cd):
    """
    Dummy pending transaction record from real transaction + construction data.
    Tx key is not sent to untrusted wallet.
    Same logic as in wallet2.cpp:sign_tx

    :param tx:
    :param cd:
    :return:
    """
    pending = xmrtypes.PendingTransaction(tx=tx, dust=0, fee=0,
                                          dust_added_to_fee=False,
                                          change_dts=cd.change_dts,
                                          selected_transfers=cd.selected_transfers,
                                          key_images='',
                                          tx_key=crypto.identity(True),
                                          additional_tx_keys=[],
                                          dests=cd.dests,
                                          multisig_sigs=[], construction_data=cd)
    return pending

