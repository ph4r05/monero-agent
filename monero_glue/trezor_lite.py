#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import traceback
import binascii

from monero_serialize import xmrtypes, xmrserialize
from monero_glue.xmr.monero import TsxData, classify_subaddresses
from . import trezor_iface, trezor_misc
from monero_glue.xmr import monero, mlsag2, ring_ct, crypto, common, key_image
from monero_glue.xmr.enc import aesgcm, chacha_poly
from monero_glue.trezor.base import TMessage, TError, TResponse, TTxHashNotMatchingError
from monero_glue.trezor.key_image_sync import KeyImageSync
from monero_glue.trezor.tsx_sign import TTransactionBuilder
from monero_glue.messages import MoneroKeyImageSync


class TrezorLite(object):
    """
    Main Trezor object.
    Provides interface to the host, packages messages.
    """
    def __init__(self):
        self.tsx_ctr = 0
        self.err_ctr = 0
        self.tsx_obj = None  # type: TTransactionBuilder
        self.ki_sync = None  # type: KeyImageSync
        self.creds = None  # type: monero.AccountCreds
        self.iface = trezor_iface.TrezorInterface()
        self.debug = True

    async def ki_exc_handler(self, e):
        """
        Handles the exception thrown in the Trezor processing.

        :param e:
        :return:
        """
        if self.debug:
            traceback.print_exc()

        self.err_ctr += 1
        self.ki_sync = None  # clear transaction object
        await self.iface.transaction_error(e)

    async def tsx_exc_handler(self, e):
        """
        Handles the exception thrown in the Trezor processing. Clears transaction state.
        We could use decorator/wrapper for message calls but not sure how uPython handles them
        so now are entry points wrapped in try-catch.

        :param e:
        :return:
        """
        if self.debug:
            traceback.print_exc()

        self.err_ctr += 1
        self.tsx_obj = None  # clear transaction object
        await self.iface.transaction_error(e)

    async def monero_get_creds(self, address_n=None, network_type=None):
        """

        :param network_type:
        :return:
        """
        return self.creds

    async def tsx_init(self, tsx_data: TsxData):
        """
        Initialize transaction state.
        :param tsx_data:
        :return:
        """
        self.tsx_ctr += 1
        self.tsx_obj = TTransactionBuilder(self, creds=self.creds)
        try:
            return await self.tsx_obj.init_transaction(tsx_data, self.tsx_ctr)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_set_input(self, src_entr):
        """
        Sets UTXO one by one.
        Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

        If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
        Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under AES-GCM() with
        key derived for exactly this purpose.

        :param src_entr
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        try:
            return await self.tsx_obj.set_input(src_entr)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.

        :return:
        """
        try:
            return await self.tsx_obj.tsx_inputs_permutation(permutation)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_input_vini(self, *args, **kwargs):
        """
        Set tx.vin[i] for incremental tx prefix hash computation.
        After sorting by key images on host.

        :return:
        """
        try:
            return await self.tsx_obj.input_vini(*args, **kwargs)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_set_output1(self, dst_entr, dst_entr_hmac):
        """
        Set destination entry one by one.
        Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.

        :param dst_entr
        :type dst_entr: xmrtypes.TxDestinationEntry
        :param dst_entr_hmac
        :return:
        """
        try:
            return await self.tsx_obj.set_out1(dst_entr, dst_entr_hmac)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_all_out1_set(self):
        """
        All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
        transaction prefix hash.
        Adds additional public keys to the tx.extra

        :return: tx.extra, tx_prefix_hash
        """
        try:
            return await self.tsx_obj.all_out1_set()

        except trezor_misc.TrezorTxPrefixHashNotMatchingError as e:
            await self.tsx_exc_handler(e)
            return TTxHashNotMatchingError(exc=e)

        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_mlsag_done(self):
        """
        MLSAG message computed.

        :return:
        """
        try:
            return await self.tsx_obj.mlsag_done()
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_sign_input(self, src_entr, vini, hmac_vini, pseudo_out, pseudo_out_hmac, alpha):
        """
        Generates a signature for one input.
        
        :return:
        """
        try:
            return await self.tsx_obj.sign_input(src_entr, vini, hmac_vini, pseudo_out, pseudo_out_hmac, alpha)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def tsx_sign_final(self, *args, **kwargs):
        """
        Final message.
        Offloading tx related data, encrypted.

        :return:
        """
        try:
            return await self.tsx_obj.final_msg(*args, **kwargs)
        except Exception as e:
            await self.tsx_exc_handler(e)
            return TError(exc=e)

    async def key_image_sync(self, msg: MoneroKeyImageSync):
        try:
            if msg.init:
                self.ki_sync = KeyImageSync(ctx=self, iface=self.iface, creds=self.creds)
                return await self.ki_sync.init(self, msg.init)

            elif msg.step:
                return await self.ki_sync.sync(self, msg.step)

            elif msg.final_msg:
                res = await self.ki_sync.final(self, msg.final_msg)
                self.ki_sync = None
                return res

            else:
                raise ValueError('Unknown error')

        except Exception as e:
            await self.ki_exc_handler(e)
            self.ki_sync = None
            return TError(exc=e)
