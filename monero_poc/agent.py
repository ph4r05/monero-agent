#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

#
# Note pickling is used for message serialization.
# This is just for the prototyping & fast PoC, pickling wont be used in the production.
# Instead, protobuf messages will be defined and parsed to avoid malicious pickling.
#

import os
import getpass
import asyncio
import argparse
import binascii
import logging
import requests
import functools
import coloredlogs
import pickle
import sys
import time
import json
import concurrent
import threading
from blessed import Terminal
from cmd2 import Cmd

from . import trace_logger
from . import cli

from monero_glue import agent_lite, agent_misc, trezor_lite
from monero_glue.xmr import wallet, monero, crypto
from monero_glue.xmr.monero import TsxData
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.WARNING, use_chroot=False)


class TrezorProxy(trezor_lite.TrezorLite):
    """
    Trezor proxy calls to the remote server
    """
    def __init__(self, url=None, *args, **kwargs):
        super().__init__()
        self.url = 'http://127.0.0.1:46123' if url is None else url
        self.endpoint = '%s/api/v1.0' % self.url

    async def ping(self):
        resp = requests.get('%s/ping' % self.endpoint)
        resp.raise_for_status()
        return resp.json()

    async def watch_only(self):
        resp = requests.get('%s/watch_only' % self.endpoint)
        resp.raise_for_status()
        return resp.json()

    async def transfer(self, method, cmd, payload):
        endp = '%s/%s' % (self.endpoint, method)
        req = {'cmd': cmd, 'payload': payload}
        resp = requests.post(endp, json=req)
        resp.raise_for_status()
        return resp.json()

    async def transfer_pickle(self, method, action, *args, **kwargs):
        logger.debug('Action: %s' % action)
        to_pickle = (args, kwargs)
        pickled_data = pickle.dumps(to_pickle)
        payload = binascii.hexlify(pickled_data).decode('utf8')

        resp = await self.transfer(method, action, payload)
        pickle_data = binascii.unhexlify(resp['payload'].encode('utf8'))
        logger.debug('Req size: %s, response size: %s' % (len(pickled_data), len(pickle_data)))

        res = pickle.loads(pickle_data)
        return res

    async def init_transaction(self, tsx_data: TsxData):
        return await self.transfer_pickle('tx_sign', 'init_transaction', tsx_data)

    async def set_tsx_input(self, src_entr):
        return await self.transfer_pickle('tx_sign', 'set_tsx_input', src_entr)

    async def tsx_inputs_permutation(self, permutation):
        return await self.transfer_pickle('tx_sign', 'tsx_inputs_permutation', permutation)

    async def tsx_input_vini(self, *args, **kwargs):
        return await self.transfer_pickle('tx_sign', 'tsx_input_vini', *args, **kwargs)

    async def set_tsx_output1(self, dst_entr, dst_entr_hmac):
        return await self.transfer_pickle('tx_sign', 'set_tsx_output1', dst_entr, dst_entr_hmac)

    async def all_out1_set(self):
        return await self.transfer_pickle('tx_sign', 'all_out1_set')

    async def tsx_mlsag_done(self):
        return await self.transfer_pickle('tx_sign', 'tsx_mlsag_done')

    async def sign_input(self, *args, **kwargs):
        return await self.transfer_pickle('tx_sign', 'sign_input', *args, **kwargs)

    async def tx_sign_final(self, *args, **kwargs):
        return await self.transfer_pickle('tx_sign', 'final', *args, **kwargs)


class HostAgent(cli.BaseCli):
    """
    Host agent wrapper
    """
    prompt = '$> '

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = None

        self.network_type = None
        self.address = None
        self.priv_view = None
        self.pub_view = None
        self.pub_spend = None
        self.network_type = None
        self.wallet_password = b''

        self.trace_logger = trace_logger.Tracelogger(logger)
        self.loop = asyncio.get_event_loop()
        self.worker_loop = asyncio.new_event_loop()
        self.worker_thread = threading.Thread(target=self.looper, args=(self.worker_loop, ))
        self.worker_thread.setDaemon(True)
        self.worker_thread.start()

        self.trezor_proxy = TrezorProxy()
        self.agent = agent_lite.Agent(self.trezor_proxy)

    def looper(self, loop):
        """
        Main looper
        :param loop:
        :return:
        """
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def submit_coro(self, coro):
        """
        Submits corroutine to the worker loop
        :param fnc:
        :param args:
        :param kwargs:
        :return:
        """
        return asyncio.run_coroutine_threadsafe(coro, self.worker_loop)

    def wait_coro(self, coro):
        """
        Runs corouting, waits for result
        :param fnc:
        :param args:
        :param kwargs:
        :return:
        """
        future = self.submit_coro(coro)
        return future.result()

    #
    # CLI
    #

    def update_intro(self):
        """
        Updates intro text for CLI header - adds version to it.
        :return:
        """
        self.intro = '-'*self.get_term_width() + \
                     '\n    Monero Trezor agent\n' + \
                     '\n' + \
                     '-' * self.get_term_width()

    #
    # Handlers
    #

    do_q = quit
    do_Q = quit

    def do_ping(self, line):
        try:
            pres = self.wait_coro(self.trezor_proxy.ping())
            print('OK %s' % pres)

        except Exception as e:
            print('Trezor not connected')
            logger.debug(e)

    def do_sign(self, line):
        self.wait_coro(self.sign_wrap(line))

    complete_sign = Cmd.path_complete

    #
    # Logic
    #

    async def is_connected(self):
        """
        Returns True if Trezor is connected
        :return:
        """
        try:
            await self.trezor_proxy.ping()
            return True

        except Exception as e:
            return False

    async def load_watchonly(self):
        """
        Loads watch-only credentials from connected Trezor
        :return:
        """
        if not await self.is_connected():
            logger.error('Trezor is not connected')
            raise agent_misc.TrezorNotRunning('Could not load watch-only credentials')

        try:
            print('Loading watch-only credentials from Trezor. Please, confirm the request on Trezor.')
            res = await self.trezor_proxy.watch_only()

            self.priv_view = crypto.b16_to_scalar(res['data']['view_key'].encode('utf8'))
            self.address = res['data']['address'].encode('utf8')
            self.network_type = res['data']['network_type']
            await self.open_with_keys(self.priv_view, self.address)

        except Exception as e:
            raise ValueError(e)

    async def open_account(self):
        """
        Opens the watch only account
        :return:
        """
        creds_passed = self.args.view_key is not None and self.args.address is not None
        account_file_set = self.args.account_file is not None
        account_file_ex = os.path.exists(self.args.account_file) if account_file_set else False
        if creds_passed:
            await self.open_account_passed()
        elif account_file_ex:
            await self.open_account_file(self.args.account_file)
        else:
            await self.load_watchonly()

        if account_file_set and not account_file_ex:
            await self.prompt_password(True)

        # Create watch only wallet file for monero-wallet-rpc
        await self.ensure_watch_only()

        # Write acquired data to the account file
        if account_file_set and not account_file_ex:
            await self.save_account(self.args.account_file)

        print('Public spend key: %s' % binascii.hexlify(crypto.encodepoint(self.pub_spend)).decode('ascii'))
        print('Public view key : %s' % binascii.hexlify(crypto.encodepoint(self.pub_view)).decode('ascii'))
        print('Address:          %s' % self.address.decode('utf8'))

    async def prompt_password(self, new_wallet=False):
        """
        Prompts password for a new wallet
        :param new_wallet:
        :return:
        """
        if new_wallet:
            passwd = self.ask_password('Creating a new wallet. Please, enter the password: ', True)
        else:
            passwd = self.ask_password('Please, enter the wallet password: ', False)
        return passwd.encode('utf8')

    async def save_account(self, file):
        """
        Stores account data
        :param file:
        :return:
        """
        with open(file, 'w') as fh:
            data = {
                'view_key': binascii.hexlify(crypto.encodeint(self.priv_view)).decode('ascii'),
                'address': self.address.decode('ascii'),
                'wallet_password': self.wallet_password.decode('utf8'),
                'WARNING': 'Agent file is not password encrypted in the PoC',
            }
            json.dump(data, fh, indent=2)

    async def ensure_watch_only(self):
        """
        Ensures watch only wallet for monero exists
        :return:
        """
        if self.args.watch_wallet is None:
            return

        key_file = '%s.keys' % self.args.watch_wallet
        if os.path.exists(key_file):
            logger.debug('Watch only wallet key file exists: %s' % key_file)
            return

        account_keys = xmrtypes.AccountKeys()
        key_data = wallet.WalletKeyData()

        wallet_data = wallet.WalletKeyFile()
        wallet_data.key_data = key_data
        wallet_data.watch_only = 1
        wallet_data.testnet = self.network_type == monero.NetworkTypes.TESTNET

        key_data.m_creation_timestamp = int(time.time())
        key_data.m_keys = account_keys

        account_keys.m_account_address = xmrtypes.AccountPublicAddress(
            m_spend_public_key=crypto.encodepoint(self.pub_spend),
            m_view_public_key=crypto.encodepoint(self.pub_view),
        )
        account_keys.m_spend_secret_key = crypto.encodeint(0)
        account_keys.m_view_secret_key = crypto.encodeint(self.priv_view)

        await wallet.save_keys_file(key_file, self.wallet_password, wallet_data)
        logger.debug('Watch-only wallet keys generated: %s' % key_file)

    async def open_account_passed(self):
        """
        Loads passed credentials
        :return:
        """
        priv_view = self.args.view_key.encode('ascii')
        self.priv_view = crypto.b16_to_scalar(priv_view)
        self.address = self.args.address.encode('ascii')
        self.network_type = monero.NetworkTypes.TESTNET if self.args.testnet else monero.NetworkTypes.MAINNET
        await self.open_with_keys(self.priv_view, self.address)

    async def open_account_file(self, file):
        """
        Opens account file
        :param file:
        :return:
        """
        with open(file) as fh:
            js = json.load(fh)

        self.wallet_password = await self.prompt_password()

        # Note the agent is not encrypted for PoC - demo.
        self.priv_view = crypto.b16_to_scalar(js['view_key'].encode('utf8'))
        self.address = js['address'].encode('utf8')

        if self.wallet_password != js['wallet_password'].encode('utf8'):
            raise ValueError('Password didnt match')

        await self.open_with_keys(self.priv_view, self.address)

    async def open_with_keys(self, view_key, address):
        """
        Processess view key private + address
        :param view_key:
        :param address:
        :return:
        """
        self.pub_view = crypto.scalarmult_base(view_key)

        version, pub_spend, pub_view = monero.decode_addr(address)
        self.pub_spend = crypto.decodepoint(pub_spend)

        if not crypto.point_eq(self.pub_view, crypto.decodepoint(pub_view)):
            raise ValueError('Computed view public key does not match the one from address')

    async def entry(self):
        """
        Entry point
        :return:
        """
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG, use_chroot=False)

        await self.open_account()

        if self.args.sign:
            return await self.sign_wrap(self.args.sign)

        self.update_intro()
        self.cmdloop()
        logger.info('Terminating')

    async def sign_wrap(self, file):
        """
        Sign wrapper
        :param file:
        :return:
        """
        if not self.priv_view:
            logger.error('View key not set, cannot sign')
            return -3

        try:
            return await self.sign(file)

        except agent_misc.TrezorReturnedError as e:
            self.trace_logger.log(e)
            print('Trezor returned an error: %s' % e)
            return 1

        except agent_misc.TrezorNotRunning as e:
            logger.error('Trezor server is not running')
            return 2

    async def sign(self, file):
        """
        Performs TX signature
        :param file:
        :return:
        """
        try:
            await self.trezor_proxy.ping()
        except Exception as e:
            raise agent_misc.TrezorNotRunning(e)

        if not os.path.exists(file):
            raise ValueError('Could not find unsigned transaction file')

        data = None
        with open(file, 'rb') as fh:
            data = fh.read()

        msg = await wallet.load_unsigned_tx(self.priv_view, data)

        # Key image sync
        # key_images = await self.agent.import_outputs(msg.transfers)
        # For now sync only spent key images to the hot wallet.
        key_images = [td.m_key_image for td in msg.transfers]

        txes = []
        pendings = []
        for tx in msg.txes:  # type: xmrtypes.TxConstructionData
            print('Signing transaction with Trezor')
            print('Please check the Trezor and confirm / reject the transaction\n')

            res = await self.agent.sign_transaction_data(tx)
            cdata = self.agent.last_transaction_data()

            # obj = await xmrobj.dump_message(None, res)
            # print(xmrjson.json_dumps(obj, indent=2))

            # Key image sync for spent TXOs
            # Updating only spent.
            for idx in range(len(tx.selected_transfers)):
                idx_mapped = cdata.source_permutation[idx]
                key_images[tx.selected_transfers[idx_mapped]] = res.vin[idx].k_image

            txes.append(await self.agent.serialize_tx(res))
            pending = wallet.construct_pending_tsx(res, tx)
            pendings.append(pending)

            # TODO: store cdata.enc_salt1, cdata.enc_salt2, cdata.enc_keys

        # Key images array has to cover all transfers sent.
        # Watch only wallet does not have key images.
        signed_tx = xmrtypes.SignedTxSet(ptx=pendings, key_images=key_images)
        signed_data = await wallet.dump_signed_tx(self.priv_view, signed_tx)
        with open('signed_monero_tx', 'wb+') as fh:
            fh.write(signed_data)
            logger.info('Signed transaction file: signed_monero_tx')

        print('Key images: %s' % [binascii.hexlify(ff).decode('utf8') for ff in key_images])
        for idx, tx in enumerate(txes):
            fname = 'transaction_%02d' % idx
            with open(fname, 'wb+') as fh:
                fh.write(tx)

            relay_fname = 'transaction_%02d_relay.sh' % idx
            hex_ctx = binascii.hexlify(tx).decode('utf8')
            with open(relay_fname, 'w+') as fh:
                fh.write('#!/bin/bash\n')
                fh.write('curl -X POST http://%s/sendrawtransaction '
                         '-d \'{"tx_as_hex":"%s", "do_not_relay":false}\' '
                         '-H \'Content-Type: application/json\'\n' % (self.args.rpc_addr, hex_ctx))

            print('Transaction %02d stored to %s, relay script: %s' % (idx, fname, relay_fname))

            if self.args.relay:
                print('Relaying...')
                payload = {'tx_as_hex': hex_ctx, 'do_not_relay': False}
                resp = requests.post('http://%s/sendrawtransaction' % (self.args.rpc_addr, ), json=payload)
                print('Relay response: %s' % resp.json())

        print('Please note that by manual relaying hot wallet key images get out of sync')
        return 0

    async def main(self):
        """
        Entry point
        :return:
        """
        parser = argparse.ArgumentParser(description='Trezor CLI based host client')

        parser.add_argument('--address', dest='address',
                            help='Full address')

        parser.add_argument('--view-key', dest='view_key',
                            help='Hex coded private view key')

        parser.add_argument('--account-file', dest='account_file',
                            help='Account file with watch-only creds')

        parser.add_argument('--watch-wallet', dest='watch_wallet',
                            help='Watch-only wallet files')

        parser.add_argument('--rpc-addr', dest='rpc_addr', default='127.0.0.1:18081',
                            help='RPC address for tsx relay')

        parser.add_argument('--relay', dest='relay', default=False, action='store_const', const=True,
                            help='Relay constructed transactions. Warning! Key images will get out of sync')

        parser.add_argument('--sign', dest='sign', default=None,
                            help='Sign the unsigned file')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging output')

        parser.add_argument('--testnet', dest='testnet', default=False, action='store_const', const=True,
                            help='Testnet')

        args_src = sys.argv
        self.args, unknown = parser.parse_known_args(args=args_src[1:])

        sys.argv = [args_src[0]]
        res = await self.entry()
        sys.argv = args_src
        return res


async def main():
    agent = HostAgent()
    res = await agent.main()
    sys.exit(res)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    # loop.run_forever()
    loop.close()


