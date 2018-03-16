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
from monero_glue import trezor, monero, common, crypto
from mnero import keccak2


class Agent(object):
    """
    Glue agent, running on host
    """
    def __init__(self, trezor):
        self.trezor = trezor

    async def transfer_unsigned(self, unsig):
        for tx in unsig.txes:
            payment_id = []
            extras = await monero.parse_extra_fields(tx.extra)
            extra_nonce = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraNonce)
            if extra_nonce and monero.has_encrypted_payment_id(extra_nonce.nonce):
                payment_id = monero.get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce)

            # Init transaction
            tsx_data = trezor.TsxData()
            tsx_data.payment_id = payment_id
            tsx_data.unlock_time = tx.unlock_time
            tsx_data.outputs = tx.dests
            tsx_data.change_dts = tx.change_dts
            await self.trezor.init_transaction(tsx_data)

            # Subaddresses
            await self.trezor.precompute_subaddr(tx.subaddr_account, tx.subaddr_indices)

            # Set transaction inputs
            for src in tx.sources:
                await self.trezor.set_tsx_input(src)
            await self.trezor.tsx_inputs_done()

            for dst in tx.dests:
                await self.trezor.set_tsx_output1(dst)

            # Unfinished proto
            await self.trezor.tsx_obj.signature(tx)

