#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
import time
import logging
import coloredlogs
from monero_glue.messages.DebugMoneroDiagRequest import DebugMoneroDiagRequest

from trezorlib import debuglink, device

from monero_glue.agent import agent_lite
from monero_glue.xmr import crypto, monero, wallet
from monero_glue.xmr import bulletproof as bp
from monero_glue.xmr import bulletproof_cl as bpcl
from monero_glue_test.base_agent_test import BaseAgentTest
from monero_glue.trezor import manager as tmanager

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


class TrezorTest(BaseAgentTest):
    def __init__(self, *args, **kwargs):
        super(TrezorTest, self).__init__(*args, **kwargs)
        self.trezor_proxy = None  # type: tmanager.Trezor
        self.agent = None  # type: agent_lite.Agent
        self.creds = None
        self.test_only_tsx = False
        self.is_debug = True
        self.do_timing = int(os.getenv('TREZOR_TEST_TIMING', '1'))
        self.do_bp_off = int(os.getenv('TREZOR_TEST_BP_OFF', '0'))
        self.time_start = None
        self.timing_bins = {}

    def get_trezor_path(self):
        tpath = os.getenv('TREZOR_PATH')
        return tpath if tpath is not None else 'webusb:020:2'  # 'udp:127.0.0.1:21324'

    def reinit_trezor(self):
        self.deinit()
        path = self.get_trezor_path()
        self.is_debug = not int(os.getenv('TREZOR_TEST_INTERACTIVE', '0'))
        self.creds = self.get_trezor_creds(0)
        self.trezor_proxy = tmanager.Trezor(path=path, debug=self.is_debug)
        self.agent = agent_lite.Agent(self.trezor_proxy, network_type=monero.NetworkTypes.TESTNET)

        client = self.trezor_proxy.client
        if self.is_debug:
            client.open()
            device.wipe(client)
            debuglink.load_device_by_mnemonic(
                client=client,
                mnemonic=self.get_trezor_mnemonics()[0],
                pin="",
                passphrase_protection=False,
                label="ph4test",
                language="english",
            )

    def deinit(self):
        try:
            if self.trezor_proxy and self.trezor_proxy.client:
                self.trezor_proxy.client.close()
        except Exception as e:
            pass

    def setUp(self):
        super().setUp()
        self.reinit_trezor()
        self.time_start = time.time()

    def tearDown(self):
        tellapsed = time.time() - self.time_start
        self.timing_bins[self._testMethodName] = tellapsed
        self.deinit()
        if self.do_timing:
            print('Test %s took %.2f s' % (self._testMethodName, tellapsed))
        super().tearDown()

    def should_test_only_tx(self):
        env_test = os.getenv('TREZOR_TEST_ONLY_TX')
        if env_test:
            return int(env_test)
        else:
            return self.test_only_tsx

    async def test_ping(self):
        await self.trezor_proxy.ping()

    async def test_get_address(self):
        if self.should_test_only_tx():
            self.skipTest("Get address skipped")
        res = await self.agent.get_address()
        self.assertIsNotNone(res)
        self.assertEqual(res.address, self.creds.address)

        ai = monero.build_address_info(self.creds, (0, 1), None, self.agent.network_type)
        res = await self.agent.get_address(account=0, minor=1, payment_id=ai.payment_id, show_display=True)
        self.assertEqual(res.address, ai.addr)

        ai = monero.build_address_info(self.creds, (10, 10), None, self.agent.network_type)
        res = await self.agent.get_address(account=10, minor=10, payment_id=ai.payment_id, show_display=True)
        self.assertEqual(res.address, ai.addr)

        # ai = monero.build_address_info(self.creds, None, [0]*8, self.agent.network_type)
        # res = await self.agent.get_address(account=0, minor=11, payment_id=ai.payment_id, show_display=True)
        # self.assertEqual(res.address, ai.addr)

    async def test_get_watch(self):
        if self.should_test_only_tx():
            self.skipTest("Get watch skipped")
        res = await self.agent.get_watch_only()
        self.assertIsNotNone(res)
        self.assertEqual(res.watch_key, crypto.encodeint(self.creds.view_key_private))
        self.assertEqual(res.address, self.creds.address)

    async def test_ki_sync(self):
        if self.should_test_only_tx():
            self.skipTest("KI sync skipped")
        ki_data = self.get_data_file("ki_sync_01.txt")
        ki_loaded = await wallet.load_exported_outputs(
            self.creds.view_key_private, ki_data
        )

        self.assertEqual(ki_loaded.m_spend_public_key, crypto.encodepoint(self.creds.spend_key_public))
        self.assertEqual(ki_loaded.m_view_public_key, crypto.encodepoint(self.creds.view_key_public))
        res = await self.agent.import_outputs(ki_loaded.tds)
        await self.verify_ki_export(res, ki_loaded)

    async def test_live_refresh(self):
        if self.should_test_only_tx() or not int(os.getenv("TREZOR_TEST_LIVE_REFRESH", '1')):
            self.skipTest("Live refresh skipped")

        creds = self.get_trezor_creds(0)
        await self.agent.live_refresh_start()
        for att in range(22):
            r = crypto.random_scalar()
            R = crypto.scalarmult_base(r)
            D = crypto.scalarmult(R, creds.view_key_private)
            subaddr = 0, att

            scalar_step1 = crypto.derive_secret_key(
                D, att, creds.spend_key_private
            )

            # step 2: add Hs(SubAddr || a || index_major || index_minor)
            if subaddr == (0, 0):
                scalar_step2 = scalar_step1
            else:
                subaddr_sk = monero.get_subaddress_secret_key(
                    creds.view_key_private, major=0, minor=att
                )
                scalar_step2 = crypto.sc_add(scalar_step1, subaddr_sk)

            pub_ver = crypto.scalarmult_base(scalar_step2)
            ki = monero.generate_key_image(crypto.encodepoint(pub_ver), scalar_step2)

            ki2 = await self.agent.live_refresh(
                creds.view_key_private,
                crypto.encodepoint(pub_ver),
                crypto.encodepoint(D),
                att,
                0,
                att
            )

            if not crypto.point_eq(ki, ki2):
                raise ValueError("Key image inconsistent")
            time.sleep(0.1)
        await self.agent.live_refresh_final()

    async def test_transactions_bp_c1_hf10(self):
        if not int(os.getenv('TREZOR_TEST_SIGN_CL1_HF10', '1')):
            self.skipTest('Tx Sign cl1 hf10 skipped')
        await self.int_test_trezor_txs(as_bulletproof=True, client_version=1, hf=10)

    def get_trezor_tsx_tests_paper(self):
        return [
          'tsx_t_uns_xx_in02-out02-ring12.txt',
          'tsx_t_uns_xx_in02-out02-ring24.txt',
          'tsx_t_uns_xx_in02-out02-ring48.txt',
          'tsx_t_uns_xx_in16-out02-ring12.txt',
          'tsx_t_uns_xx_in32-out02-ring12.txt',
          'tsx_t_uns_xx_in64-out02-ring12.txt',
          'tsx_t_uns_xx_in128-out02-ring12.txt',
          'tsx_t_uns_xx_in02-out16-ring12.txt',
          'tsx_t_uns_xx_in16-out16-ring12.txt',
        ]

    def get_testing_files(self):
        test_paperset = int(os.getenv('TREZOR_TEST_PAPER', 0))
        fl = self.get_trezor_tsx_tests_paper() if test_paperset else self.get_trezor_tsx_tests()
        env_num = os.getenv('TREZOR_TEST_NUM_TX')
        if env_num:
            try:
                env_num = int(env_num)
                return fl[:env_num]
            except Exception as e:
                pass
        return fl

    async def int_test_trezor_txs(self, as_bulletproof=False, files=None, client_version=0, hf=9):
        self.agent.client_version = client_version
        self.agent.hf = hf

        files = self.get_testing_files() if not files else files
        creds = self.get_trezor_creds(0)
        all_creds = self.get_all_trezor_creds()

        last_test_ok = True
        last_test_name = None

        for fl in files:
            if not last_test_ok:
                print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! FAIL: %s' % last_test_name)

            print('Testing[bp=%s,cl=%s,hf=%s]: %s' % (as_bulletproof, client_version, hf, fl))
            last_test_ok = False
            last_test_name = fl
            tstart = time.time()

            with self.subTest(msg=fl):
                unsigned_tx_c = self.get_data_file(fl)
                unsigned_tx = await wallet.load_unsigned_tx(
                    creds.view_key_private, unsigned_tx_c
                )

                for tx in unsigned_tx.txes:
                    if as_bulletproof:
                        tx.use_rct = False
                        tx.use_bulletproofs = True

                await self.tx_sign_test(self.agent, unsigned_tx, creds, all_creds, fl)
                await self.agent.get_address()  # resets flow
                last_test_ok = True
                print('OK in %.2f s' % (time.time() - tstart))

    async def test_comm_diag(self):
        if not self.do_bp_off:
            self.skipTest("Comm skipped")
        msg = DebugMoneroDiagRequest(ins=0, p1=0, p2=0)
        for i in range(100):
            await self.trezor_proxy.call(msg)

    async def test_bp_off(self):
        if not self.do_bp_off:
            self.skipTest("BP offloading not tested")
        ln = int(os.getenv('BP_M', '16'))

        async def diagMessenger(p1=0, p2=0, params=None, buffers=None):
            msg = DebugMoneroDiagRequest(ins=7, p1=p1, p2=p2, pd=params, data3=buffers)
            return (await self.trezor_proxy.call(msg)).data3

        cl = bpcl.BulletproofClient(ln, messenger=diagMessenger)
        proof = await cl.compute_bp()

        bpi = bp.BulletProofBuilder()
        bpi.verify_batch([proof])

        logger.info('M: %s, Nmsgs %s, Sent %s, Recv %s, time %.2f' % (ln, cl.n_msgs, cl.n_sent, cl.n_recv, cl.prove_time))
