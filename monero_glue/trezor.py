#!/usr/bin/env python
# -*- coding: utf-8 -*-
import binascii

from mnero import mininero
from monero_serialize import xmrtypes, xmrserialize
from .monero import TsxData, classify_subaddresses, addr_to_hash
from . import monero, crypto
from . import common as common


class WalletCreds(object):
    """
    Stores wallet private keys
    """
    def __init__(self, view_key_private=None, spend_key_private=None, view_key_public=None, spend_key_public=None, address=None):
        self.view_key_private = view_key_private
        self.view_key_public = view_key_public
        self.spend_key_private = spend_key_private
        self.spend_key_public = spend_key_public
        self.address = address

    @classmethod
    def new_wallet(cls, priv_view_key, priv_spend_key):
        pub_view_key = mininero.public_key(priv_view_key)
        pub_spend_key = mininero.public_key(priv_spend_key)
        addr = mininero.encode_addr(mininero.netVersion(),
                                    binascii.hexlify(pub_spend_key),
                                    binascii.hexlify(pub_view_key))
        return cls(view_key_private=priv_view_key, spend_key_private=priv_spend_key,
                   view_key_public=pub_view_key, spend_key_public=pub_spend_key,
                   address=addr)


class Trezor(object):
    """
    Main Trezor object
    """
    def __init__(self):
        self.tsx_ctr = 0
        self.tsx_obj = None
        self.key_master = None
        self.key_hmac = None
        self.creds = None  # type: WalletCreds

    async def init_transaction(self, tsx_data: TsxData):
        self.tsx_ctr += 1
        self.tsx_obj = TTransaction(self)
        self.tsx_obj.init_transaction(tsx_data)

        # Generate master key H(TsxData || r || c_tsx)
        writer = common.get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(tsx_data)
        await xmrserialize.dump_uvarint(writer, self.tsx_obj.r)
        await xmrserialize.dump_uvarint(writer, self.tsx_ctr)
        self.key_master = writer.get_digest()
        self.key_hmac = common.keccak_hash(b'hmac' + self.key_master)

    async def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        :param account:
        :param indices:
        :return:
        """
        self.tsx_obj.precompute_subaddr(account, indices)

    async def set_tsx_input(self, src_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        self.tsx_obj.set_input(src_entr)


class TTransaction(object):
    """
    Transaction builder
    """
    def __init__(self, trezor=None):
        self.trezor = trezor
        self.r = None  # txkey
        self.r_pub = None
        self.tsx_data = None
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.additional_tx_keys = []
        self.inp_idx = -1
        self.summary_inputs_money = 0
        self.subaddresses = {}

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

    def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        :param account:
        :param indices:
        :return:
        """
        pkeys = []
        for idx in indices:
            if account == 0 and idx == 0:
                pkeys.append(self.trezor.creds.spend_key_public)
                self.subaddresses[self.trezor.creds.spend_key_public] = (0,0)
                continue

            m = monero.get_subaddress_secret_key(self.trezor.creds.view_key_private, major=account, minor=idx)
            pub = mininero.public_key(m)
            pkeys.append(pub)
            self.subaddresses[pub] = (account, indices)


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

        out_key = src_entr.outputs[src_entr.real_output][1].dest
        monero.generate_key_image_helper(self.trezor.creds, self.subaddresses, out_key,
                                         src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys,
                                         src_entr.real_output_in_tx_index, None, None)



