#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import random
import base64
import unittest
import pkg_resources
import requests
import asyncio
import aiounittest
import binascii

import monero_serialize as xmrser
from monero_serialize import xmrserialize, xmrtypes
from monero_glue import trezor, trezor_lite, monero, common, crypto
from mnero import keccak2


class TData(object):
    """
    Agent transaction-scoped data
    """
    def __init__(self):
        self.tsx_data = None  # type: monero.TsxData
        self.tx = xmrtypes.Transaction(version=2, vin=[], vout=[], extra=[])
        self.tx_in_hmacs = []
        self.tx_out_hmacs = []
        self.tx_out_rsigs = []
        self.tx_out_pk = []
        self.tx_out_ecdh = []
        self.source_permutation = []
        self.alphas = []
        self.pseudo_outs = []


class Agent(object):
    """
    Glue agent, running on host
    """
    def __init__(self, trezor):
        self.trezor = trezor  # type: trezor_lite.TrezorLite
        self.ct = None  # type: TData

    def is_simple(self, rv):
        """
        True if simpe
        :param rv:
        :return:
        """
        return rv.type in [xmrtypes.RctType.Simple, xmrtypes.RctType.SimpleBulletproof]

    def is_bulletproof(self, rv):
        """
        True if bulletproof
        :param rv:
        :return:
        """
        return rv.type in [xmrtypes.RctType.FullBulletproof, xmrtypes.RctType.SimpleBulletproof]

    async def transfer_unsigned(self, unsig):
        txes = []
        for tx in unsig.txes:
            self.ct = TData()

            payment_id = []
            extras = await monero.parse_extra_fields(tx.extra)
            extra_nonce = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraNonce)
            if extra_nonce and monero.has_encrypted_payment_id(extra_nonce.nonce):
                payment_id = monero.get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce)

            # Init transaction
            tsx_data = trezor.TsxData()
            tsx_data.version = 1
            tsx_data.payment_id = payment_id
            tsx_data.unlock_time = tx.unlock_time
            tsx_data.outputs = tx.dests
            tsx_data.change_dts = tx.change_dts
            tsx_data.num_inputs = len(tx.sources)
            tsx_data.mixin = len(tx.sources[0].outputs)
            self.ct.tx.unlock_time = tx.unlock_time

            self.ct.tsx_data = tsx_data
            await self.trezor.init_transaction(tsx_data)

            # Subaddresses precomputation - needed for this transaction
            await self.trezor.precompute_subaddr(tx.subaddr_account, tx.subaddr_indices)

            # Set transaction inputs
            for idx, src in enumerate(tx.sources):
                vini, vini_hmac, pseudo_out, alpha_enc = await self.trezor.set_tsx_input(src)
                self.ct.tx.vin.append(vini)
                self.ct.tx_in_hmacs.append(vini_hmac)
                self.ct.pseudo_outs.append(pseudo_out)
                self.ct.alphas.append(alpha_enc)

            await self.trezor.tsx_inputs_done()

            # Sort key image
            self.ct.source_permutation = list(range(len(tx.sources)))
            self.ct.source_permutation.sort(key=lambda x: self.ct.tx.vin[x].k_image)

            def swapper(x, y):
                self.ct.tx.vin[x], self.ct.tx.vin[y] = self.ct.tx.vin[y], self.ct.tx.vin[x]
                self.ct.tx_in_hmacs[x], self.ct.tx_in_hmacs[y] = self.ct.tx_in_hmacs[y], self.ct.tx_in_hmacs[x]
                self.ct.pseudo_outs[x], self.ct.pseudo_outs[y] = self.ct.pseudo_outs[y], self.ct.pseudo_outs[x]
                self.ct.alphas[x], self.ct.alphas[y] = self.ct.alphas[y], self.ct.alphas[x]
                tx.sources[x], tx.sources[y] = tx.sources[y], tx.sources[x]

            common.apply_permutation(self.ct.source_permutation, swapper)
            await self.trezor.tsx_inputs_permutation(self.ct.source_permutation)

            # Set vin_i back - tx prefix hashing
            for idx in range(len(self.ct.tx.vin)):
                await self.trezor.tsx_input_vini(tx.sources[idx], self.ct.tx.vin[idx], self.ct.tx_in_hmacs[idx])

            # Set transaction outputs
            for dst in tx.dests:
                vouti, vouti_mac, rsig, out_pk, ecdh_info = await self.trezor.set_tsx_output1(dst)
                self.ct.tx.vout.append(vouti)
                self.ct.tx_out_hmacs.append(vouti_mac)
                self.ct.tx_out_rsigs.append(rsig)
                self.ct.tx_out_pk.append(out_pk)
                self.ct.tx_out_ecdh.append(ecdh_info)

            tx_extra, tx_prefix_hash = await self.trezor.all_out1_set()
            self.ct.tx.extra = list(bytearray(tx_extra))

            # Verify transaction prefix hash correctness, tx hash in one pass
            tx_prefix_hash_computed = await monero.get_transaction_prefix_hash(self.ct.tx)
            if tx_prefix_hash != tx_prefix_hash_computed:
                raise ValueError('Transaction prefix has does not match')

            # RctSig
            rv = await self.trezor.tsx_gen_rv()

            # Pseudo outputs
            for idx in range(len(self.ct.pseudo_outs)):
                await self.trezor.tsx_mlsag_pseudo_out(self.ct.pseudo_outs[idx])

            if self.is_simple(rv):
                if self.is_bulletproof(rv):
                    rv.p.pseudoOuts = [x[0] for x in self.ct.pseudo_outs]
                else:
                    rv.pseudoOuts = [x[0] for x in self.ct.pseudo_outs]

            # Range proof
            rv.p.rangeSigs = []
            rv.outPk = []
            rv.ecdhInfo = []
            for idx in range(len(self.ct.tx_out_rsigs)):
                await self.trezor.tsx_mlsag_rangeproof(self.ct.tx_out_rsigs[idx])
                rv.p.rangeSigs.append(self.ct.tx_out_rsigs[idx][0])
                rv.outPk.append(self.ct.tx_out_pk[idx])
                rv.ecdhInfo.append(self.ct.tx_out_ecdh[idx])

            # MLSAG message check
            mlsag_hash = await self.trezor.tsx_mlsag_done()
            mlsag_hash_computed = await monero.get_pre_mlsag_hash(rv)
            if mlsag_hash != mlsag_hash_computed:
                raise ValueError('Pre MLSAG hash has does not match')

            # Sign each input
            rv.p.MGs = []
            for idx, src in enumerate(tx.sources):
                mg = await self.trezor.sign_input(src, self.ct.tx.vin[idx], self.ct.tx_in_hmacs[idx],
                                                  self.ct.pseudo_outs[idx],
                                                  self.ct.alphas[idx])
                rv.p.MGs.append(mg)

            self.ct.tx.signatures = []
            self.ct.tx.rct_signatures = rv
            del rv

            # Serialize response
            writer = xmrserialize.MemoryReaderWriter()
            ar1 = xmrserialize.Archive(writer, True)
            await ar1.message(self.ct.tx, msg_type=xmrtypes.Transaction)

            txes.append(bytes(writer.buffer))

        return txes


