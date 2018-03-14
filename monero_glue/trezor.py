#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii

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
        pub_view_key = crypto.scalarmult_base(priv_view_key)
        pub_spend_key = crypto.scalarmult_base(priv_spend_key)
        addr = monero.encode_addr(monero.net_version(),
                                  binascii.hexlify(crypto.encodepoint(pub_spend_key)),
                                  binascii.hexlify(crypto.encodepoint(pub_view_key)))
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

    async def set_tsx_output1(self, dst_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxDestinationEntry
        :return:
        """
        self.tsx_obj.set_out1(dst_entr)


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
        self.input_secrets = []
        self.subaddresses = {}
        self.tx = xmrtypes.Transaction(vin=[], vout=[], extra=[])

    def gen_r(self):
        """
        Generates a new transaction key pair.
        :return:
        """
        self.r = crypto.random_scalar()
        self.r_pub = crypto.public_key(self.r)

    def init_transaction(self, tsx_data):
        """
        Initializes a new transaction.
        :param tsx_data:
        :return:
        """
        self.tsx_data = tsx_data
        self.gen_r()

        # Additional keys
        class_res = classify_subaddresses(tsx_data.outputs, tsx_data.change_dts.addr if tsx_data.change_dts else None)
        num_stdaddresses, num_subaddresses, _ = class_res
        self.need_additional_txkeys = num_subaddresses > 0 and (num_stdaddresses > 0 or num_subaddresses > 1)
        if self.need_additional_txkeys:
            self.additional_tx_keys.append(crypto.random_scalar())

        # Extra processing, payment id
        self.tx.version = 2
        self.process_payment_id()

    def process_payment_id(self):
        """
        Payment id -> extra
        :return:
        """


    def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        Subaddresses have to be stored in encoded form - unique representation.
        Single point can have multiple extended coordinates representation - would not match during subaddress search.
        :param account:
        :param indices:
        :return:
        """
        for idx in indices:
            if account == 0 and idx == 0:
                self.subaddresses[crypto.encodepoint(self.trezor.creds.spend_key_public)] = (0,0)
                continue

            m = monero.get_subaddress_secret_key(self.trezor.creds.view_key_private, major=account, minor=idx)
            pub = crypto.encodepoint(crypto.scalarmult_base(m))
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

        out_key = crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].dest)
        tx_key = crypto.decodepoint(src_entr.real_out_tx_key)
        additional_keys = [crypto.decodepoint(x) for x in src_entr.real_out_additional_tx_keys]
        secs = monero.generate_key_image_helper(self.trezor.creds, self.subaddresses, out_key,
                                                tx_key,
                                                additional_keys,
                                                src_entr.real_output_in_tx_index)
        self.input_secrets.append(secs)

        xi, ki, di = secs

        # Construct tx.vin
        vini = xmrtypes.TxinToKey(amount=src_entr.amount, k_image=crypto.encodepoint(ki))
        vini.key_offsets = [x[0] for x in src_entr.outputs]
        vini.key_offsets = monero.absolute_output_offsets_to_relative(vini.key_offsets)
        self.tx.vin.append(vini)

        hmac_vini = common.keccak_hash(self.trezor.key_hmac + b'txin' + xmrserialize.dump_uvarint_b(self.inp_idx))
        # TODO: HMAC(T_in,i || I_in, vin_i)

        return vini

    def set_out1(self, dest_entr):
        """
        Set destination entry
        :param src_entr
        :type src_entr: xmrtypes.TxDestinationEntry
        :return:
        """
        # if dest_entr.amount <= 0 and tx.version <= 1: pass






