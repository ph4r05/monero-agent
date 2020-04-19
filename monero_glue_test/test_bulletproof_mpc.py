#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
from binascii import unhexlify
import logging
import aiounittest
from monero_serialize.xmrtypes import Bulletproof

from monero_glue.xmr import crypto
from monero_glue.xmr import bulletproof as bp
from monero_glue.xmr import bulletproof_cl as bpcl


logger = logging.getLogger(__name__)


class BulletproofMPCTest(aiounittest.AsyncTestCase):

    def __init__(self, *args, **kwargs):
        super(BulletproofMPCTest, self).__init__(*args, **kwargs)

    def can_test(self):
        return crypto.get_backend().has_crypto_into_functions()

    def skip_if_cannot_test(self):
        if not self.can_test():
            self.skipTest("Crypto backend does not implement required functions")

    async def test_prove_offload_batch2(self):
        await self.run_mpc_booltest(2)

    async def test_prove_offload_batch4(self):
        await self.run_mpc_booltest(4)

    async def test_prove_offload_batch16(self):
        await self.run_mpc_booltest(16)

    async def run_mpc_booltest(self, m=4):
        runner = bpcl.BulletproofMPCRunner()

        async def step_messenger(p1=0, p2=0, params=None, buffers=None):
            return await runner.step(p1, p2, params, buffers)

        cl = bpcl.BulletproofClient(m, messenger=step_messenger)
        proof = await cl.compute_bp()

        bpi = bp.BulletProofBuilder()
        bpi.verify_batch([proof])

        logger.info('M: %s, Nmsgs %s, Sent %s, Recv %s, time %.2f' % (m, cl.n_msgs, cl.n_sent, cl.n_recv, cl.prove_time))
