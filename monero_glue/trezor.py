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
        self.creds = None  # type: WalletCreds

    async def init_transaction(self, tsx_data: TsxData):
        self.tsx_ctr += 1
        self.tsx_obj = TTransaction(self)
        self.tsx_obj.creds = self.creds
        await self.tsx_obj.init_transaction(tsx_data, self.tsx_ctr)

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
        await self.tsx_obj.set_input(src_entr)

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """
        await self.tsx_obj.tsx_inputs_done()

    async def set_tsx_output1(self, dst_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxDestinationEntry
        :return:
        """
        await self.tsx_obj.set_out1(dst_entr)


class TTransaction(object):
    """
    Transaction builder
    """
    def __init__(self, trezor=None):
        self.trezor = trezor  # type: Trezor
        self.creds = None  # type: WalletCreds
        self.key_master = None
        self.key_hmac = None

        self.r = None  # txkey
        self.r_pub = None

        self.tsx_data = None  # type: monero.TsxData
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.additional_tx_keys = []
        self.additional_tx_public_keys = []
        self.inp_idx = -1
        self.out_idx = -1
        self.summary_inputs_money = 0
        self.summary_outs_money = 0
        self.input_secrets = []
        self.subaddresses = {}
        self.tx = xmrtypes.Transaction(vin=[], vout=[], extra=[])
        self.source_permutation = []  # sorted by key images

    def gen_r(self):
        """
        Generates a new transaction key pair.
        :return:
        """
        self.r = crypto.random_scalar()
        self.r_pub = crypto.scalarmult_base(self.r)

    async def init_transaction(self, tsx_data, tsx_ctr):
        """
        Initializes a new transaction.
        :param tsx_data:
        :param tsx_ctr:
        :return:
        """
        self.tsx_data = tsx_data
        self.gen_r()

        # Additional keys
        class_res = classify_subaddresses(tsx_data.outputs, tsx_data.change_dts.addr if tsx_data.change_dts else None)
        num_stdaddresses, num_subaddresses, single_dest_subaddress = class_res

        # if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
        if num_stdaddresses == 0 and num_subaddresses == 1:
            self.r_pub = crypto.ge_scalarmult(self.r, single_dest_subaddress.m_spend_public_key)

        self.need_additional_txkeys = num_subaddresses > 0 and (num_stdaddresses > 0 or num_subaddresses > 1)
        if self.need_additional_txkeys:
            self.additional_tx_keys.append(crypto.random_scalar())

        # Extra processing, payment id
        self.tx.version = 2
        await self.process_payment_id()
        await self.compute_hmac_keys(tsx_ctr)

    async def process_payment_id(self):
        """
        Payment id -> extra
        :return:
        """
        if self.tsx_data.payment_id is None or len(self.tsx_data.payment_id) == 0:
            return

        change_addr = self.tsx_data.change_dts.addr if self.tsx_data.change_dts else None
        view_key_pub_enc = monero.get_destination_view_key_pub(self.tsx_data.outputs, change_addr)
        if view_key_pub_enc == crypto.NULL_KEY_ENC:
            raise ValueError('Destinations have to have exactly one output to support encrypted payment ids')

        view_key_pub = crypto.decodepoint(view_key_pub_enc)
        payment_id_encr = monero.encrypt_payment_id(self.tsx_data.payment_id, view_key_pub, self.r)

        extra_nonce = monero.set_encrypted_payment_id_to_tx_extra_nonce(payment_id_encr)
        self.tx.extra = monero.add_extra_nonce_to_tx_extra([], extra_nonce)

    async def compute_hmac_keys(self, tsx_ctr):
        """
        Generate master key H(TsxData || r || c_tsx)
        :return:
        """
        writer = common.get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(self.tsx_data)
        await xmrserialize.dump_uvarint(writer, self.r)
        await xmrserialize.dump_uvarint(writer, tsx_ctr)
        self.key_master = writer.get_digest()
        self.key_hmac = common.keccak_hash(b'hmac' + self.key_master)

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

    async def set_input(self, src_entr):
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

        hmac_vini = common.keccak_hash(self.key_hmac + b'txin' + xmrserialize.dump_uvarint_b(self.inp_idx))
        # TODO: HMAC(T_in,i || I_in, vin_i)

        return vini

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """

        # Sort tx.in by key image
        self.source_permutation = list(range(self.inp_idx+1))
        self.source_permutation.sort(key=lambda x: self.tx.vin[x].k_image)

        def swapper(x, y):
            self.tx.vin[x], self.tx.vin[y] = self.tx.vin[y], self.tx.vin[x]

        common.apply_permutation(self.source_permutation, swapper)

        # Set public key to the extra
        self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraPubKey)
        monero.add_tx_pub_key_to_extra(self.tx.extra, self.r_pub)

    async def set_out1(self, dst_entr):
        """
        Set destination entry
        :param src_entr
        :type src_entr: xmrtypes.TxDestinationEntry
        :return:
        """
        self.out_idx += 1
        change_addr = self.tsx_data.change_dts.addr if self.tsx_data.change_dts else None

        if dst_entr.amount <= 0 and self.tx.version <= 1:
            raise ValueError('Destination with wrong amount: %s' % dst_entr.amount)

        additional_txkey = None
        if self.need_additional_txkeys:
            if dst_entr.is_subaddress:
                additional_txkey = crypto.ge_scalarmult(self.additional_tx_keys[self.out_idx],
                                                        crypto.decodepoint(dst_entr.addr.m_spend_public_key))
            else:
                additional_txkey = crypto.ge_scalarmult_base(self.additional_tx_keys[self.out_idx])

        if self.need_additional_txkeys:
            self.additional_tx_public_keys.append(additional_txkey)

        if change_addr and dst_entr.addr == change_addr:
            # sending change to yourself; derivation = a*R
            derivation = monero.generate_key_derivation(self.r_pub, self.creds.view_key_private)

        else:
            # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
            deriv_priv = additional_txkey if dst_entr.is_subaddress and self.need_additional_txkeys else self.r
            derivation = monero.generate_key_derivation(self.creds.view_key_public, deriv_priv)

        tx_out_key = crypto.derive_public_key(derivation, self.out_idx, crypto.decodepoint(dst_entr.addr.m_spend_public_key))
        tk = xmrtypes.TxoutToKey(key=tx_out_key)
        tx_out = xmrtypes.TxOut(amount=dst_entr.amount, target=tk)
        self.tx.vout.append(tx_out)
        self.summary_outs_money += dst_entr.amount

        # Last output?
        if self.out_idx + 1 == len(self.tsx_data.outputs):
            await self.all_out1_set()

    async def all_out1_set(self):
        """
        All out1 set phase
        :return:
        """
        self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
        if self.need_additional_txkeys:
            await monero.add_additional_tx_pub_keys_to_extra(self.tx.extra, self.additional_tx_public_keys)

        if self.summary_outs_money > self.summary_inputs_money:
            raise ValueError('Transaction inputs money (%s) less than outputs money (%s)'
                             % (self.summary_inputs_money, self.summary_outs_money))

