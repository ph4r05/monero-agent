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


class Trezor(object):
    def __init__(self):
        self.tsx_ctr = 0
        self.tsx_data = None
        self.tsx_obj = None
        self.key_master = None
        self.key_hmac = None

    async def init_transaction(self, tsx_data: TsxData):
        self.tsx_ctr += 1
        self.tsx_data = tsx_data
        self.tsx_obj = TTransaction()
        self.tsx_obj.init_transaction(tsx_data)

        # Generate master key H(TsxData || r || c_tsx)
        writer = common.get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(tsx_data)
        await xmrserialize.dump_uvarint(writer, self.tsx_obj.r)
        await xmrserialize.dump_uvarint(writer, self.tsx_ctr)
        self.key_master = writer.get_digest()
        self.key_hmac = common.keccak_hash(b'hmac' + self.key_master)

    async def set_tsx_input(self, src_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        self.tsx_obj.set_input(src_entr)



class TTransaction(object):
    def __init__(self):
        self.r = None  # txkey
        self.r_pub = None
        self.tsx_data = None
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.additional_tx_keys = []
        self.inp_idx = -1
        self.summary_inputs_money = 0

    def gen_r(self):
        self.r = mininero.randomScalar()
        self.r_pub = mininero.public_key(self.r)

    def init_transaction(self, tsx_data):
        self.tsx_data = tsx_data
        self.gen_r()

        # Additional keys
        class_res = classify_subaddresses(tsx_data.outputs, tsx_data.change_dts.addr if tsx_data.change_dts else None)
        num_stdaddresses, num_subaddresses, _ = class_res
        self.need_additional_txkeys = num_subaddresses > 0 and (num_stdaddresses > 0 or num_subaddresses > 1)
        if self.need_additional_txkeys:
            self.additional_tx_keys.append(mininero.randomScalar())

        # TODO: extra processing, payment id
        # ...

    def set_input(self, src_entr):
        """
        :param src_entr:
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        self.inp_idx += 1
        if src_entr.real_output >= len(src_entr.outputs):
            raise ValueError('real_output index %s bigger than output_keys.size()' % (src_entr.real_output, len(src_entr.outputs)))
        self.summary_inputs_money += src_entr.amount




