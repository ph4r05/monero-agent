#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

#
# Note pickling is used for message serialization.
# This is just for the prototyping & fast PoC, pickling wont be used in the production.
# Instead, protobuf messages will be defined and parsed to avoid malicious pickling.
#

import sys
import os
import time
import json
import asyncio
import argparse
import binascii
import logging
import traceback
import threading
import coloredlogs
import pickle
import collections

import eventlet
from eventlet import wsgi
from flask import Flask, jsonify, request, abort

from . import cli
from monero_poc import misc
from monero_glue import trezor_lite, trezor_iface
from monero_glue.xmr import monero, crypto, common, wallet
from monero_glue.xmr.core import mnemonic
from monero_glue.misc.bip import bip32

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.WARNING, use_chroot=False)
eventlet.monkey_patch(socket=True)


class TrezorInterface(trezor_iface.TrezorInterface):
    def __init__(self, server=None):
        self.server = server
        self.tsx_waiter = misc.CliPrompt(pre_wait_hook=server.update_prompt)
        self.ki_sync_waiter = misc.CliPrompt(pre_wait_hook=server.update_prompt)
        self.tsx_data = None
        self.confirmed_result = False

    def get_tx_data(self):
        return self.tsx_data

    @property
    def in_confirmation(self):
        return self.tsx_waiter.in_confirmation

    def confirmation(self, confirmed):
        self.confirmed_result = confirmed
        self.tsx_waiter.confirmation(confirmed)

    async def confirm_transaction(self, tsx_data):
        self.confirmed_result = False
        self.tsx_data = tsx_data
        try:
            self.server.on_confirm_start()
            self.tsx_waiter.wait_confirmation()
            return self.confirmed_result

        finally:
            self.tsx_data = None

    async def transaction_signed(self):
        logger.debug('Transaction signed')

    async def transaction_error(self, *args, **kwargs):
        logger.error('Transaction error: %s %s' % (args, kwargs))

    async def transaction_finished(self):
        self.server.on_transaction_signed()

    async def transaction_step(self, step, sub_step=None):
        logger.debug('Transaction step: %s, sub step: %s' % (step, sub_step))

    async def confirm_ki_sync(self, init_msg):
        self.server.on_confirm_ki_sync(init_msg)
        self.ki_sync_waiter.wait_confirmation()
        return self.ki_sync_waiter.confirmed_result

    async def ki_error(self, e):
        logger.error('ki sync error: %s' % e)

    async def ki_step(self, i):
        logger.debug('ki sync progress: %s' % i)

    async def ki_finished(self):
        logger.info('ki sync finished')


class TrezorServer(cli.BaseCli):
    """
    Trezor emulator server
    """
    prompt = '$> '

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.trez = None  # type: trezor_lite.TrezorLite
        self.args = None
        self.network_type = None
        self.creds = None  # type: monero.AccountCreds
        self.port = 46123
        self.trez_iface = TrezorInterface(self)
        self.account_data = None
        self.ki_sync_data = None

        self.loop = asyncio.get_event_loop()
        self.running = True
        self.stop_event = threading.Event()
        self.local_data = threading.local()
        self.watch_only_waiter = misc.CliPrompt(pre_wait_hook=self.update_prompt)
        self.ui_lock = threading.Lock()
        self.use_werkzeug = False
        self.thread_rest = None
        self.thread_loop = None
        self.rest_loop = None
        self.worker_loop = None

        self.debug = False
        self.server = None
        self.flask = Flask(__name__)

    #
    # CLI related
    #

    def update_intro(self):
        """
        Updates intro text for CLI header - adds version to it.
        :return:
        """
        self.intro = '-'*self.get_term_width() + \
                     '\n    Trezor server\n'

        if self.creds:
            self.intro += ('\n    Account address: %s ' % self.creds.address.decode('utf8'))
        else:
            self.intro += ('\n    Account not initialized, call new_wallet')

        self.intro += ('\n    Running on: 127.0.0.1:%s ' % self.port) + \
                      '\n' + \
                      '-' * self.get_term_width()

    def update_prompt(self):
        """
        Prompt update
        :return:
        """
        flags = []
        if self.watch_only_waiter.in_confirmation:
            flags.append('W?')
        if self.trez_iface.in_confirmation:
            flags.append('T?')
        if self.trez_iface.ki_sync_waiter.in_confirmation:
            flags.append('K?')

        flags_str = '|'.join(flags)
        flags_suffix = '|' + flags_str if len(flags_str) > 0 else ''

        addr_str = self.creds.address.decode('ascii')[:6] if self.creds else 'UNINIT'
        self.prompt = '[trezor %s%s]: ' % (addr_str, flags_suffix)

    #
    # Server related
    #

    def shutdown_server(self):
        """
        Shutdown flask server
        :return:
        """
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def terminating(self):
        """
        Set state to terminating
        :return:
        """
        self.running = False
        self.stop_event.set()

    def wait_coro(self, coro):
        """
        Waits on the coroutine, for flask server
        :param coro:
        :return:
        """
        # Running on a different thread is not supported in flask:
        # future = asyncio.run_coroutine_threadsafe(self.on_ping(request=request), self.worker_loop)
        # return future.result()

        # Running on the common rest thread
        # return self.rest_loop.run_until_complete(self.on_ping(request=request))

        # Option: create a new loop as this worker is inside own thread
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(coro)
        loop.close()
        return res

    def init_rest(self):
        """
        Initializes rest server
        :return:
        """
        @self.flask.route('/api/v1.0/ping', methods=['GET'])
        def keep_alive():
            return self.wait_coro(self.on_ping(request=request))

        @self.flask.route('/api/v1.0/watch_only', methods=['GET'])
        def watch_only():
            return self.wait_coro(self.on_watch_only(request=request))

        @self.flask.route('/api/v1.0/tx_sign', methods=['GET', 'POST'])
        def tx_sign():
            return self.wait_coro(self.on_tx_sign(request=request)) \

        @self.flask.route('/api/v1.0/ki_sync', methods=['GET', 'POST'])
        def ki_sync():
            return self.wait_coro(self.on_ki_sync(request=request))

    def wsgi_options(self):
        """
        Returns kwargs for wsgi server
        :return:
        """
        kwargs = dict()
        if False:
            kwargs['minimum_chunk_size'] = 1
        return kwargs

    def serve_werkzeug(self):
        """
        Developer local server, not for production use
        :return:
        """
        r = self.flask.run(debug=self.debug, port=self.port, threaded=True)
        logger.info('Started werkzeug server: %s' % r)

    def serve_eventlet(self):
        """
        Eventlet server, fast async, for production use
        Warning: Eventlet is tricky to work concurrently with classical threading locks

        :return:
        """
        listener = eventlet.listen(('0.0.0.0', self.port))
        logger.info('Starting Eventlet listener %s for Flask %s' % (listener, self.flask))
        wsgi.server(listener, self.flask, **self.wsgi_options())

    #
    # Handlers
    #

    async def on_ping(self, request=None):
        """
        Simple ping
        :param request:
        :return:
        """
        return jsonify({'result': True})

    async def on_watch_only(self, request=None):
        """
        Exports watch only credentials
        :param request:
        :return:
        """
        if not self.creds:
            logger.warning('Agent asks for watch-only credentials, Trezor not initialized')
            return abort(406)

        if self.watch_only_waiter.in_confirmation:
            logger.warning('Agent asks for watch-only credentials concurrently')
            return abort(406)
        
        # Prompt user to confirm.
        self.on_watchonly()
        confirmed = self.watch_only_waiter.wait_confirmation()

        if not confirmed:
            logger.warning('Watch only rejected')
            return abort(403)

        logger.info('Returning watch only credentials...')
        res = {
            'view_key': binascii.hexlify(crypto.encodeint(self.creds.view_key_private)).decode('ascii'),
            'address': self.creds.address.decode('ascii'),
            'network_type': self.network_type,
        }
        return jsonify({'result': True, 'data': res})

    async def on_tx_sign(self, request=None):
        """
        TX sign
        :param request:
        :return:
        """
        js = request.json
        cmd = js['cmd']
        logger.debug('Action: %s' % cmd)
        args, kwargs = self.unpickle_args(js) if 'payload' in js else ([], {})

        if not self.trez:
            logger.warning('Transaction signing request on unitialized Trezor')
            return abort(404)

        if cmd == 'init_transaction':
            res = await self.trez.init_transaction(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'set_tsx_input':
            res = await self.trez.set_tsx_input(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'tsx_inputs_permutation':
            res = await self.trez.tsx_inputs_permutation(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'tsx_input_vini':
            res = await self.trez.tsx_input_vini(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'set_tsx_output1':
            res = await self.trez.set_tsx_output1(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'all_out1_set':
            res = await self.trez.all_out1_set(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'tsx_mlsag_done':
            res = await self.trez.tsx_mlsag_done(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'sign_input':
            res = await self.trez.sign_input(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'final':
            res = await self.trez.tx_sign_final(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        else:
            return abort(405)

    async def on_ki_sync(self, request=None):
        """
        Key image sync
        :param request:
        :return:
        """
        js = request.json
        cmd = js['cmd']
        logger.debug('Action: %s' % cmd)
        args, kwargs = self.unpickle_args(js) if 'payload' in js else ([], {})

        if not self.trez:
            logger.warning('KeyImage sync request on unitialized Trezor')
            return abort(404)

        if cmd == 'ask':
            res = await self.trez.key_image_sync_ask(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'transfer':
            res = await self.trez.key_image_sync_transfer(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        elif cmd == 'final':
            res = await self.trez.key_image_sync_final(*args, **kwargs)
            return jsonify({'result': True, 'payload': self.pickle_res(res)})

        else:
            return abort(405)

    def unpickle_args(self, js):
        return pickle.loads(binascii.unhexlify(js['payload'].encode('utf8')))

    def pickle_res(self, res):
        return binascii.hexlify(pickle.dumps(res)).decode('utf8')

    #
    # Terminal
    #

    do_q = quit
    do_Q = quit

    def do_new_wallet(self, line):
        self.create_wallet(line)

    def do_address(self, line):
        self.poutput(self.creds.address.decode('ascii'))

    def do_keys(self, line):
        print('Spend key priv:   0x%s' % binascii.hexlify(crypto.encodeint(self.creds.spend_key_private)).decode('ascii'))
        print('View key priv:    0x%s' % binascii.hexlify(crypto.encodeint(self.creds.view_key_private)).decode('ascii'))
        print('')
        print('Spend key pub:    0x%s' % binascii.hexlify(crypto.encodepoint(self.creds.spend_key_public)).decode('ascii'))
        print('View key pub:     0x%s' % binascii.hexlify(crypto.encodepoint(self.creds.view_key_public)).decode('ascii'))

    def on_watchonly(self):
        self.poutput('-' * 80)
        self.poutput('Watch-only request received\nEnter W to confirm/reject\n')

    def on_confirm_start(self):
        self.poutput('-' * 80)
        self.poutput('Transaction confirmation procedure\nEnter T to start\n')

    def on_transaction_signed(self):
        self.poutput('-' * 80)
        self.poutput('Transaction was successfully signed\n')

    def on_confirm_ki_sync(self, msg):
        self.ki_sync_data = msg
        self.poutput('-' * 80)
        self.poutput('Key image sync procedure\nEnter K to start\n')

    def conv_disp_amount(self, amount):
        return wallet.conv_disp_amount(amount)

    def do_T(self, line):
        if not self.trez_iface.in_confirmation:
            self.poutput('No transaction in progress')
            return

        tsx_data = self.trez_iface.get_tx_data()
        self.poutput('Confirming transaction:')
        self.poutput('- ' * 40)
        if tsx_data.payment_id:
            self.poutput('  Payment ID: %s' % binascii.hexlify(tsx_data.payment_id).decode('utf8'))

        self.poutput('  Unlock time: %s' % tsx_data.unlock_time)
        self.poutput('  UTXOs: %s' % tsx_data.num_inputs)
        self.poutput('  Mixin: %s' % tsx_data.mixin)

        chg = tsx_data.change_dts
        addr_chg = monero.public_addr_encode(chg.addr, chg.is_subaddress, self.network_type) if chg else None

        for idx, out in enumerate(tsx_data.outputs):
            addr = monero.public_addr_encode(out.addr, out.is_subaddress, self.network_type)
            if addr != addr_chg:
                self.poutput('  Output %2d: %12.8f to %s, sub: %s'
                             % (idx, self.conv_disp_amount(out.amount), addr.decode('utf8'), out.is_subaddress))
            else:
                self.poutput('  Change:    %12.8f to %s, sub: %s'
                             % (self.conv_disp_amount(out.amount), addr.decode('utf8'), out.is_subaddress))

        self.poutput('  Fee: %.8f' % self.conv_disp_amount(tsx_data.fee))
        self.poutput('  Account: %s' % tsx_data.account)

        self.poutput('- ' * 40)
        result = self.select([(0, 'Confirm the transaction'), (1, 'Reject')], 'Do you confirm the transaction? ')
        self.poutput('\n')
        self.trez_iface.confirmation(result == 0)
        self.update_prompt()

    def do_W(self, line):
        if not self.watch_only_waiter.in_confirmation:
            self.poutput('No prompt')
            return

        result = self.select([(0, 'Confirm'), (1, 'Reject')],
                             'Do you confirm sending watch-only credentials to the client? ')

        self.poutput('\n')
        self.watch_only_waiter.confirmation(result == 0)
        self.update_prompt()

    def do_K(self, line):
        if not self.trez_iface.ki_sync_waiter.in_confirmation:
            self.poutput('No prompt')
            return

        self.poutput('Agent asks to perform key image sync.')
        self.poutput('Syncing %s outputs' % self.ki_sync_data.num)

        result = self.select([(0, 'Confirm'), (1, 'Reject')],
                             'Do you want to proceed? ')

        self.poutput('\n')
        self.trez_iface.ki_sync_waiter.confirmation(result == 0)
        self.update_prompt()

    do_t = do_T
    do_w = do_W
    do_k = do_K

    #
    # Work
    #

    def loop_work(self, loop):
        """
        Looping worker
        :return:
        """
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def rest_thread_work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('REST thread started %s %s %s dbg: %s'
                    % (os.getpid(), os.getppid(), threading.current_thread(), self.debug))
        try:
            self.worker_loop = asyncio.new_event_loop()
            self.rest_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.rest_loop)

            worker = threading.Thread(target=self.loop_work, args=(self.worker_loop,))
            worker.setDaemon(True)
            worker.start()

            self.init_rest()
            if self.debug or self.use_werkzeug:
                self.serve_werkzeug()
            else:
                self.serve_eventlet()

            logger.info('Terminating flask: %s' % self.flask)

        except Exception as e:
            logger.error('Exception: %s' % e)
            logger.error(traceback.format_exc())

        self.terminating()
        logger.info('Work loop terminated')

    def rest_server_boot(self):
        """
        Boost the server
        :return:
        """
        self.thread_rest = threading.Thread(target=self.rest_thread_work, args=())
        self.thread_rest.setDaemon(True)
        self.thread_rest.start()

    def create_wallet(self, line):
        """
        Creates a new account
        :return:
        """
        if self.args.account_file:
            if os.path.exists(self.args.account_file):
                logger.error('Wallet file exists, could not overwrite')
                return

        print('Generating new wallet...')
        seed = crypto.random_bytes(32)

        wl = bip32.Wallet.from_master_secret(seed)
        seed_bip32_words, seed_bip32_words_indices = wl.to_seed_words()
        seed_bip32_b58 = wl.serialize_b58()

        # Generate private keys based on the gen mechanism. Bip44 path + Monero backward compatible
        data = wl.get_child_for_path("m/44'/128'/0'/0/0")
        to_hash = data.chain_code + binascii.unhexlify(data.private_key.get_key())

        # to_hash is initial seed in the Monero sense, recoverable from this seed
        hashed = crypto.cn_fast_hash(to_hash)
        electrum_words = ' '.join(mnemonic.mn_encode(hashed))

        keys = monero.generate_monero_keys(hashed)
        spend_sec, spend_pub, view_sec, view_pub = keys

        print('Seed:             0x%s' % binascii.hexlify(seed).decode('ascii'))
        print('Seed bip39 words: %s' % ' '.join(seed_bip32_words))
        print('Seed bip32 b58:   %s' % seed_bip32_b58)

        print('Seed Monero:      0x%s' % binascii.hexlify(hashed).decode('ascii'))
        print('Seed Monero wrds: %s' % electrum_words)

        print('')
        print('Spend key priv:   0x%s' % binascii.hexlify(crypto.encodeint(spend_sec)).decode('ascii'))
        print('View key priv:    0x%s' % binascii.hexlify(crypto.encodeint(view_sec)).decode('ascii'))
        print('')
        print('Spend key pub:    0x%s' % binascii.hexlify(crypto.encodepoint(spend_pub)).decode('ascii'))
        print('View key pub:     0x%s' % binascii.hexlify(crypto.encodepoint(view_pub)).decode('ascii'))

        self.init_with_keys(spend_sec, view_sec)
        print('')
        print('Address:          %s' % self.creds.address.decode('ascii'))

        self.account_data = collections.OrderedDict()
        self.account_data['seed'] = binascii.hexlify(seed).decode('ascii')
        self.account_data['spend_key'] = binascii.hexlify(crypto.encodeint(spend_sec)).decode('ascii')
        self.account_data['view_key'] = binascii.hexlify(crypto.encodeint(view_sec)).decode('ascii')
        self.account_data['meta'] = collections.OrderedDict([
            ('addr', self.creds.address.decode('ascii')),
            ('bip44_seed', binascii.hexlify(seed).decode('ascii')),
            ('bip32_39_words', ' '.join(seed_bip32_words)),
            ('bip32_b58', seed_bip32_b58),
            ('monero_seed', binascii.hexlify(hashed).decode('ascii')),
            ('monero_words', electrum_words),
        ])

        if self.args.account_file:
            with open(self.args.account_file, 'w+') as fh:
                json.dump(self.account_data, fh, indent=2)
        print('Wallet generated')
        self.update_prompt()

    async def open_account(self):
        """
        Handles account open / management
        :return:
        """
        self.update_intro()
        self.update_prompt()

        priv_spend_key = None
        priv_view_key = None

        if not self.args.account_file and not self.args.spend_key:
            logger.debug('No account file nor spend key. Please generate new account')
            return

        acc_file_exists = False
        if self.args.account_file:
            acc_file_exists = os.path.exists(self.args.account_file)

            if acc_file_exists and self.args.spend_key:
                logger.error('Account file exists, spend key is ignored')
            if acc_file_exists and self.args.view_key:
                logger.error('Account file exists, view key is ignored')
            if acc_file_exists:
                with open(self.args.account_file) as fh:
                    self.account_data = json.load(fh)
                priv_spend_key = crypto.decodeint(binascii.unhexlify(self.account_data['spend_key'].encode('ascii')))
                priv_view_key = crypto.decodeint(binascii.unhexlify(self.account_data['view_key'].encode('ascii')))

        if not acc_file_exists and self.args.spend_key:
            priv_view = self.args.view_key.encode('utf8')
            priv_spend = self.args.spend_key.encode('utf8')
            priv_view_key = crypto.b16_to_scalar(priv_view)
            priv_spend_key = crypto.b16_to_scalar(priv_spend)

            self.account_data = {'spend_key': priv_spend_key, 'view_key': priv_view_key}
            with open(self.args.account_file, 'w') as fh:
                json.dump(self.account_data, fh, indent=2)

        if priv_spend_key and priv_view_key:
            self.init_with_keys(priv_spend_key, priv_view_key)

    def init_with_keys(self, priv_spend_key, priv_view_key):
        """
        Initializes Trezor classes with the private keys
        :return:
        """
        self.creds = monero.AccountCreds.new_wallet(priv_view_key, priv_spend_key, self.network_type)
        self.update_intro()

        self.trez = trezor_lite.TrezorLite()
        self.trez.creds = self.creds
        self.trez.iface = self.trez_iface
        self.update_prompt()

    async def entry(self):
        """
        pass
        :return:
        """
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG, use_chroot=False)

        self.network_type = monero.NetworkTypes.MAINNET
        if self.args.testnet:
            self.network_type = monero.NetworkTypes.TESTNET
        elif self.args.stagenet:
            self.network_type = monero.NetworkTypes.STAGENET

        await self.open_account()

        logging.info('Starting rest server...')
        self.rest_server_boot()
        time.sleep(1)

        self.cmdloop()
        self.terminating()

    async def main(self):
        """
        Entry point
        :return:
        """
        parser = argparse.ArgumentParser(description='Trezor server')

        parser.add_argument('--testnet', dest='testnet', default=False, action='store_const', const=True,
                            help='Testnet')

        parser.add_argument('--stagenet', dest='stagenet', default=False, action='store_const', const=True,
                            help='Stagenet')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debug')

        parser.add_argument('--account-file', dest='account_file',
                            help='Trezor account file to use / open')

        parser.add_argument('--view-key', dest='view_key',
                            help='Hex coded private view key')

        parser.add_argument('--spend-key', dest='spend_key',
                            help='Hex coded private spend key')

        args_src = sys.argv
        self.args, unknown = parser.parse_known_args(args=args_src[1:])

        sys.argv = [args_src[0]]
        await self.entry()
        sys.argv = args_src


async def main():
    agent = TrezorServer()
    await agent.main()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    # loop.run_forever()
    loop.close()


