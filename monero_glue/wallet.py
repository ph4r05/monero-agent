#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from . import crypto
from . import chacha
from monero_serialize import xmrboost, xmrtypes, xmrserialize

UNSIGNED_TX_PREFIX = b"Monero unsigned tx set\004"
SIGNED_TX_PREFIX = b"Monero signed tx set\004"
MULTISIG_UNSIGNED_TX_PREFIX = b"Monero multisig unsigned tx set\001"


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
                                          tx_key=b'\x01' + b'\x00' * 31,
                                          additional_tx_keys=[],
                                          dests=cd.dests,
                                          multisig_sigs=[], construction_data=cd)
    return pending

