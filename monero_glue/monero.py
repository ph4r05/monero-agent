#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mnero import mininero
from monero_serialize import xmrtypes, xmrserialize
from . import common as common


class TsxData(xmrserialize.MessageType):
    """
    TsxData, initial input to the transaction processing.
    Serialization structure for easy hashing.
    """
    FIELDS = [
        ('payment_id', xmrserialize.BlobType),
        ('outputs', xmrserialize.ContainerType, xmrtypes.TxDestinationEntry),
        ('change_dts', xmrtypes.TxDestinationEntry),
    ]

    def __init__(self, payment_id=None, outputs=None, change_dts=None, **kwargs):
        super().__init__(**kwargs)

        self.payment_id = payment_id
        self.change_dts = change_dts
        self.outputs = outputs if outputs else []  # type: list[xmrtypes.TxDestinationEntry]


def addr_to_hash(addr: xmrtypes.AccountPublicAddress):
    """
    Creates hashable address representation
    :param addr:
    :return:
    """
    return bytes(addr.m_spend_public_key + addr.m_view_public_key)


def classify_subaddresses(tx_dests, change_addr : xmrtypes.AccountPublicAddress):
    """
    Classify destination subaddresses
    void classify_addresses()
    :param tx_dests:
    :type tx_dests: list[xmrtypes.TxDestinationEntry]
    :param change_addr:
    :return:
    """
    num_stdaddresses = 0
    num_subaddresses = 0
    single_dest_subaddress = None
    addr_set = set()
    for tx in tx_dests:
        if change_addr and change_addr == tx.addr:
            continue
        addr_hashed = addr_to_hash(tx.addr)
        if addr_hashed in addr_set:
            continue
        addr_set.add(addr_hashed)
        if tx.is_subaddress:
            num_subaddresses+=1
            single_dest_subaddress = tx.addr
        else:
            num_stdaddresses+=1
    return num_stdaddresses, num_subaddresses, single_dest_subaddress


async def parse_extra_fields(extra_buff):
    """
    Parses extra buffer to the extra fields vector
    :param extra_buff:
    :return:
    """
    extras = []
    rw = xmrserialize.MemoryReaderWriter(extra_buff)
    ar2 = xmrserialize.Archive(rw, False)
    while len(rw.buffer) > 0:
        extras.append(await ar2.variant(elem_type=xmrtypes.TxExtraField))
    return extras


def find_tx_extra_field_by_type(extra_fields, msg):
    """
    Finds given message type in the extra array, or returns None if not found
    :param extra_fields:
    :param msg:
    :return:
    """
    for x in extra_fields:
        if isinstance(x, msg):
            return x


def has_encrypted_payment_id(extra_nonce):
    """
    Returns true if encrypted payment id is present
    :param extra_nonce:
    :return:
    """
    return len(extra_nonce) == 9 and extra_nonce[0] == 1


def get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce):
    """
    Extracts encrypted payment id from extra
    :param extra_nonce:
    :return:
    """
    if 9 != len(extra_nonce):
        raise ValueError('Nonce size mismatch')
    if 0x1 != extra_nonce[0]:
        raise ValueError('Nonce payment type invalid')
    return extra_nonce[1:]


def get_destination_view_key_pub(destinations, change_addr=None):
    """
    Returns destination address public view key
    :param destinations:
    :type destinations: list[xmrtypes.TxDestinationEntry]
    :param change_addr:
    :return:
    """
    addr = xmrtypes.AccountPublicAddress(m_spend_public_key=[0]*32, m_view_public_key=[0]*32)
    count = 0
    for dest in destinations:
        if dest.amount == 0:
            continue
        if change_addr and dest.addr == change_addr:
            continue
        if dest.addr == addr:
            continue
        if count > 0:
            return [0]*32
        addr = dest.addr
        count += 1
    return addr.m_view_public_key


