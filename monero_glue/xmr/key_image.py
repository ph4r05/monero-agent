#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from monero_serialize import xmrtypes, xmrserialize
from monero_glue.xmr import mlsag2, ring_ct, crypto, common, monero
from monero_glue.misc import b58_mnr
import collections
import binascii


class SubAddrIndicesList(xmrserialize.MessageType):
    __slots__ = ['account', 'minor_indices']
    FIELDS = [
        ('account', xmrserialize.UVarintType),
        ('minor_indices', xmrserialize.ContainerType, xmrserialize.UVarintType),
    ]


class KeyImageExportInit(xmrserialize.MessageType):
    """
    Initializes key image sync. Commitment
    """
    __slots__ = ['num', 'hash', 'subs']
    FIELDS = [
        ('num', xmrserialize.UVarintType),  # number of outputs to gen
        ('hash', xmrtypes.Hash),  # aggregate hash commitment
        ('subs', xmrserialize.ContainerType, SubAddrIndicesList),  # aggregated sub addresses indices
    ]


class TransferDetails(xmrserialize.MessageType):
    """
    Transfer details for key image sync needs
    """
    __slots__ = ['out_key', 'tx_pub_key', 'additional_tx_pub_keys', 'm_internal_output_index']
    FIELDS = [
        ('out_key', xmrtypes.ECPublicKey),
        ('tx_pub_key', xmrtypes.ECPublicKey),
        ('additional_tx_pub_keys', xmrserialize.ContainerType, xmrtypes.ECPublicKey),
        ('m_internal_output_index', xmrserialize.UVarintType),
    ]


class ExportedKeyImage(xmrserialize.MessageType):
    """
    Exported key image
    """
    __slots__ = ['iv', 'tag', 'blob']
    FIELDS = [
        ('iv', xmrserialize.BlobType),   # enc IV
        ('tag', xmrserialize.BlobType),  # enc tag
        ('blob', xmrserialize.BlobType),  # encrypted ki || sig
    ]


async def yield_key_image_data(outputs):
    """
    Process outputs, yields out_key, tx pub key, additional tx pub keys data
    yield in async from py3.6

    :param outputs:
    :return:
    """
    res = []
    for idx, td in enumerate(outputs):  # type: xmrtypes.TransferDetails
        if common.is_empty(td.m_tx.vout):
            raise ValueError('Tx with no outputs %s' % idx)

        tx_pub_key = await monero.get_tx_pub_key_from_received_outs(td)
        extras = await monero.parse_extra_fields(list(td.m_tx.extra))
        additional_pub_keys = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraAdditionalPubKeys)
        out_key = td.m_tx.vout[td.m_internal_output_index].target.key
        cres = TransferDetails(out_key=out_key, tx_pub_key=tx_pub_key,
                               additional_tx_pub_keys=additional_pub_keys.data if additional_pub_keys else None,
                               m_internal_output_index=td.m_internal_output_index)
        res.append(cres)
    return res


def compute_hash(rr):
    """
    Hash over output to ki-sync
    :param rr:
    :type rr: TransferDetails
    :return:
    """
    buff = b''
    buff += rr.out_key
    buff += rr.tx_pub_key
    if rr.additional_tx_pub_keys:
        buff += b''.join(rr.additional_tx_pub_keys)
    buff += xmrserialize.dump_uvarint_b(rr.m_internal_output_index)

    return crypto.cn_fast_hash(buff)


async def generate_commitment(outputs):
    """
    Generates num, hash commitment for initial message for ki syc
    :param outputs:
    :type outputs: list[xmrtypes.TransferDetails]
    :return:
    """
    hashes = []
    sub_indices = collections.defaultdict(lambda: set())
    for out in outputs:
        sub_indices[out.m_subaddr_index.major].add(out.m_subaddr_index.minor)

    num = 0
    iter = await yield_key_image_data(outputs)
    for rr in iter:  # type: TransferDetails
        hash = compute_hash(rr)
        hashes.append(hash)
        num += 1

    final_hash = crypto.cn_fast_hash(b''.join(hashes))
    indices = []

    for major in sub_indices:
        indices.append(SubAddrIndicesList(account=major, minor_indices=list(sub_indices[major])))

    return KeyImageExportInit(num=num, hash=final_hash, subs=indices)


async def export_key_image(creds, subaddresses, td):
    """
    Key image export
    :param creds:
    :param subaddresses:
    :param td:
    :return:
    """
    out_key = crypto.decodepoint(td.out_key)
    tx_pub_key = crypto.decodepoint(td.tx_pub_key)
    additional_tx_pub_keys = []
    if not common.is_empty(td.additional_tx_pub_keys):
        additional_tx_pub_keys = [crypto.decodepoint(x) for x in td.additional_tx_pub_keys]

    ki, sig = ring_ct.export_key_image(creds, subaddresses, out_key, tx_pub_key,
                                       additional_tx_pub_keys, td.m_internal_output_index)

    return ki, sig





