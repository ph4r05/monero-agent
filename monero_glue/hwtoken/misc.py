#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_glue import protobuf
from monero_glue.compat import gc
from monero_glue.messages import (
    MoneroAccountPublicAddress,
    MoneroMultisigKLRki,
    MoneroOutputEntry,
    MoneroRctKey,
    MoneroTransactionData,
    MoneroTransactionDestinationEntry,
    MoneroTransactionSourceEntry,
)
from monero_glue.xmr import crypto
from monero_serialize import xmrserialize, xmrtypes


class TrezorError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


class TrezorSecurityError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorInvalidStateError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorTxPrefixHashNotMatchingError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorChangeAddressError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class StdObj(object):
    def __init__(self, **kwargs):
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


def compute_tx_key(spend_key_private, tx_prefix_hash, salt=None, rand_mult=None):
    """

    :param spend_key_private:
    :param tx_prefix_hash:
    :param salt:
    :param rand_mult:
    :return:
    """
    if not salt:
        salt = crypto.random_bytes(32)

    if not rand_mult:
        rand_mult_num = crypto.random_scalar()
        rand_mult = crypto.encodeint(rand_mult_num)
    else:
        rand_mult_num = crypto.decodeint(rand_mult)

    rand_inp = crypto.sc_add(spend_key_private, rand_mult_num)
    passwd = crypto.keccak_2hash(crypto.encodeint(rand_inp) + tx_prefix_hash)
    tx_key = crypto.compute_hmac(salt, passwd)
    # tx_key = crypto.pbkdf2(passwd, salt, count=100)
    return tx_key, salt, rand_mult


def translate_monero_dest_entry_pb(dst_entry: xmrtypes.TxDestinationEntry):
    d = MoneroTransactionDestinationEntry(
        amount=dst_entry.amount,
        is_subaddress=dst_entry.is_subaddress,
        addr=MoneroAccountPublicAddress(
            spend_public_key=dst_entry.addr.m_spend_public_key,
            view_public_key=dst_entry.addr.m_view_public_key,
        ),
    )
    return d


def translate_monero_src_entry_pb(src_entry: xmrtypes.TxSourceEntry):
    d = MoneroTransactionSourceEntry()
    d.outputs = [
        MoneroOutputEntry(idx=x[0], key=MoneroRctKey(dest=x[1].dest, mask=x[1].mask))
        for x in src_entry.outputs
    ]
    d.real_output = src_entry.real_output
    d.real_out_tx_key = src_entry.real_out_tx_key
    d.real_out_additional_tx_keys = list(src_entry.real_out_additional_tx_keys)
    d.real_output_in_tx_index = src_entry.real_output_in_tx_index
    d.amount = src_entry.amount
    d.rct = src_entry.rct
    d.mask = src_entry.mask
    if src_entry.multisig_kLRki:
        s = src_entry.multisig_kLRki
        src_entry.multisig_kLRki = MoneroMultisigKLRki(K=s.K, L=s.L, R=s.R, ki=s.ki)
    return d


async def parse_msg(bts, msg):
    reader = xmrserialize.MemoryReaderWriter(bytearray(bts))
    ar = xmrserialize.Archive(reader, False)
    return await ar.message(msg)


async def parse_pb_msg(bts, msg):
    reader = xmrserialize.MemoryReaderWriter(bytearray(bts))
    return await protobuf.load_message(reader, msg)


async def parse_vini(bts):
    return await parse_msg(bts, xmrtypes.TxinToKey())


async def dump_msg(msg, preallocate=None, msg_type=None):
    writer = xmrserialize.MemoryReaderWriter(preallocate=preallocate)
    ar = xmrserialize.Archive(writer, True)
    await ar.message(msg, msg_type=msg_type)
    return writer.get_buffer()


async def dump_pb_msg(msg):
    writer = xmrserialize.MemoryReaderWriter()
    await protobuf.dump_message(writer, msg)
    return bytes(writer.get_buffer())


async def dump_msg_gc(msg, preallocate=None, msg_type=None, del_msg=False):
    b = await dump_msg(msg, preallocate=preallocate, msg_type=msg_type)
    if del_msg:
        del msg

    import gc

    gc.collect()
    return b


def dst_entry_to_stdobj(dst):
    if dst is None:
        return None

    addr = StdObj(
        spend_public_key=dst.addr.spend_public_key,
        view_public_key=dst.addr.view_public_key,
    )
    return StdObj(amount=dst.amount, addr=addr, is_subaddress=dst.is_subaddress)
