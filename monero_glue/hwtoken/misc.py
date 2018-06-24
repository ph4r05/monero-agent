#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_serialize import xmrtypes, xmrserialize
from monero_glue.xmr import common, crypto
from monero_glue.xmr.monero import TsxData
from monero_glue.messages import MoneroTxDestinationEntry, MoneroTsxData, MoneroAccountPublicAddress
from monero_glue import protobuf


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
    tx_key = crypto.pbkdf2(passwd, salt, count=100)
    return tx_key, salt, rand_mult


def translate_monero_dest_entry(dst_entry: MoneroTxDestinationEntry):
    d = xmrtypes.TxDestinationEntry()
    d.amount = dst_entry.amount
    d.is_subaddress = dst_entry.is_subaddress
    d.addr = xmrtypes.AccountPublicAddress(m_spend_public_key=dst_entry.addr.m_spend_public_key,
                                           m_view_public_key=dst_entry.addr.m_view_public_key)
    return d


def translate_monero_dest_entry_pb(dst_entry: xmrtypes.TxDestinationEntry):
    d = MoneroTxDestinationEntry(amount=dst_entry.amount,
                                 is_subaddress=dst_entry.is_subaddress,
                                 addr=MoneroAccountPublicAddress(m_spend_public_key=dst_entry.addr.m_spend_public_key,
                                                                 m_view_public_key=dst_entry.addr.m_view_public_key))
    return d


async def translate_tsx_data(tsx_data: MoneroTsxData):
    tsxd = TsxData()
    for fld in TsxData.MFIELDS:
        fname = fld[0]
        if hasattr(tsx_data, fname):
            setattr(tsxd, fname, getattr(tsx_data, fname))

    if tsx_data.change_dts:
        tsxd.change_dts = translate_monero_dest_entry(tsx_data.change_dts)

    tsxd.outputs = [translate_monero_dest_entry(x) for x in tsx_data.outputs]
    return tsxd


async def translate_tsx_data_pb(tsx_data: TsxData):
    tsxd = MoneroTsxData()
    for fld in TsxData.MFIELDS:
        fname = fld[0]
        if hasattr(tsx_data, fname):
            setattr(tsxd, fname, getattr(tsx_data, fname))

    if tsx_data.change_dts:
        tsxd.change_dts = translate_monero_dest_entry_pb(tsx_data.change_dts)

    tsxd.outputs = [translate_monero_dest_entry_pb(x) for x in tsx_data.outputs]
    return tsxd


async def parse_msg(bts, msg):
    reader = xmrserialize.MemoryReaderWriter(bytearray(bts))
    ar = xmrserialize.Archive(reader, False)
    return await ar.message(msg)


async def parse_pb_msg(bts, msg):
    reader = xmrserialize.MemoryReaderWriter(bytearray(bts))
    return await protobuf.load_message(reader, msg)


async def parse_src_entry(bts):
    return await parse_msg(bts, xmrtypes.TxSourceEntry())


async def parse_dst_entry(bts):
    return await parse_msg(bts, xmrtypes.TxDestinationEntry())


async def parse_vini(bts):
    return await parse_msg(bts, xmrtypes.TxinToKey())


async def dump_msg(msg):
    writer = xmrserialize.MemoryReaderWriter()
    ar = xmrserialize.Archive(writer, True)
    await ar.message(msg)
    return bytes(writer.buffer)


async def dump_pb_msg(msg):
    writer = xmrserialize.MemoryReaderWriter()
    await protobuf.dump_message(writer, msg)
    return bytes(writer.buffer)



