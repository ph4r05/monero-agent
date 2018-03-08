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
    ]

    def __init__(self, payment_id=None, outputs=None, **kwargs):
        super().__init__(**kwargs)

        self.payment_id = payment_id
        self.outputs = outputs if outputs else []  # type: list[xmrtypes.TxDestinationEntry]


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
        self.tsx_obj.init_transaction()

        # Generate master key H(TsxData || r || c_tsx)
        writer = common.get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(tsx_data)
        await xmrserialize.dump_uvarint(writer, self.tsx_obj.r)
        await xmrserialize.dump_uvarint(writer, self.tsx_ctr)
        self.key_master = writer.get_digest()
        self.key_hmac = common.keccak_hash(b'hmac' + self.key_master)


class TTransaction(object):
    def __init__(self):
        self.r = None
        self.r_pub = None

    def gen_r(self):
        self.r = mininero.randomScalar()
        self.r_pub = mininero.public_key(self.r)

    def init_transaction(self):
        self.gen_r()



