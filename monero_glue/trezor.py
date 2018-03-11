#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mnero import mininero
from monero_serialize import xmrtypes, xmrserialize
from .monero import TsxData, classify_subaddresses, addr_to_hash
from . import monero
from . import common as common


class Trezor(object):
    def __init__(self):
        self.tsx_ctr = 0
        self.tsx_obj = None
        self.key_master = None
        self.key_hmac = None

    async def init_transaction(self, tsx_data: TsxData):
        self.tsx_ctr += 1
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




