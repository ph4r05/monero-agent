#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2020

import binascii
from binascii import unhexlify
import logging
import aiounittest

from monero_glue.hwtoken import misc
from monero_glue.xmr import crypto
from monero_glue.xmr import transaction_builder
from monero_glue.xmr.sub.creds import AccountCreds
from monero_glue.xmr.sub.xmr_net import NetworkTypes
from monero_serialize.xmrtypes import (
    UnsignedTxSet,
    TxConstructionData,
)

logger = logging.getLogger(__name__)


class TxBuilderTest(aiounittest.AsyncTestCase):
    nettype = NetworkTypes.TESTNET
    creds = []

    def __init__(self, *args, **kwargs):
        super(TxBuilderTest, self).__init__(*args, **kwargs)

    def gen_creds(self):
        if self.creds:
            return
        for i in range(3):
            self.creds.append(AccountCreds.new_wallet(crypto.random_scalar(), crypto.random_scalar(), self.nettype))
        return self.creds

    def gen_builder(self):
        self.gen_creds()
        bld = transaction_builder.TransactionBuilder()
        bld.src_keys = self.creds[0]
        bld.dest_keys = self.creds[1:]
        bld.nettype = self.nettype
        bld.account_idx = 0
        bld.fee = 15000
        return bld

    async def try_deserialize(self, uns):
        msg = UnsignedTxSet()
        await misc.parse_msg(uns, msg)
        return msg

    async def test_builder_simple(self):
        bld = self.gen_builder()
        await bld.gen_input(10000, sub_minor=0, additionals=False)
        await bld.gen_input(90000, sub_minor=0, additionals=True)
        await bld.gen_output(75000, sub_major=0, sub_minor=0)
        await bld.gen_change()
        await bld.build()
        r = await bld.serialize_unsigned()
        await self.try_deserialize(r)

    async def test_builder_c1(self):
        bld = self.gen_builder()
        await bld.gen_input(10000, sub_minor=0, additionals=False)
        await bld.gen_input(20000, sub_minor=0, additionals=True)
        await bld.gen_input(50000, sub_minor=2, additionals=True)
        await bld.gen_input(70000, sub_minor=3, additionals=False)
        await bld.gen_output(75000, sub_major=1, sub_minor=0)
        await bld.gen_output(15000, sub_major=1, sub_minor=10)
        await bld.gen_output(15000, sub_major=1, sub_minor=3)
        await bld.gen_change()
        await bld.build()
        r = await bld.serialize_unsigned()
        await self.try_deserialize(r)
