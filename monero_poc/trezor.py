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
import json
import time
import asyncio
import argparse
import binascii
import logging
import traceback
import threading
import coloredlogs
import pickle
from blessed import Terminal
from cmd2 import Cmd

import eventlet
from eventlet import wsgi
from flask import Flask, jsonify, request, abort

from monero_glue import crypto, monero, trezor_lite, trezor_iface
from monero_serialize import xmrserialize, xmrtypes, xmrobj, xmrjson, xmrboost


logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.WARNING, use_chroot=False)
eventlet.monkey_patch(socket=True)


class TrezorInterface(trezor_iface.TrezorInterface):
    def __init__(self, server=None):
        self.server = server
        self.in_confirmation = False
        self.tsx_data = None
        self.conf_evt = None
        self.confirmed_result = False

    def get_tx_data(self):
        return self.tsx_data

    def confirmation(self, confirmed):
        self.confirmed_result = confirmed
        self.conf_evt.set()

    async def confirm_transaction(self, tsx_data):
        self.in_confirmation = True
        self.confirmed_result = False
        self.tsx_data = tsx_data
        self.conf_evt = threading.Event()
        try:
            self.server.on_confirm_start()
            self.conf_evt.wait()

            return self.confirmed_result

        finally:
            self.in_confirmation = False
            self.tsx_data = None


class TrezorServer(Cmd):
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
        self.t = Terminal()
        self.trez_iface = TrezorInterface(self)

        self.loop = asyncio.get_event_loop()
        self.running = True
        self.stop_event = threading.Event()
        self.local_data = threading.local()
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
                     '\n    Trezor server\n' + \
                     ('\n    Account address: %s ' % self.creds.address.decode('utf8')) + \
                     ('\n    Running on: 127.0.0.1:%s ' % self.port) + \
                     '\n' + \
                     '-' * self.get_term_width()

    def get_term_width(self):
        """
        Returns terminal width
        :return: terminal width in characters or 80 if exception encountered
        """
        try:
            width = self.t.width
            if width is None or width <= 0:
                return 80

            return width
        except:
            pass
        return 80

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

        @self.flask.route('/api/v1.0/tx_sign', methods=['GET', 'POST'])
        def tx_sign():
            return self.wait_coro(self.on_tx_sign(request=request))

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

    def unpickle_args(self, js):
        return pickle.loads(binascii.unhexlify(js['payload'].encode('utf8')))

    def pickle_res(self, res):
        return binascii.hexlify(pickle.dumps(res)).decode('utf8')

    #
    # Terminal
    #

    do_q = quit
    do_Q = quit

    def on_confirm_start(self):
        self.poutput('-' * 80)
        self.poutput('Transaction confirmation procedure\nEnter T to start\n')

    def conv_disp_amount(self, amount):
        return amount / float(10**monero.DISPLAY_DECIMAL_POINT)

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
        self.trez_iface.confirmation(result == 0)

    do_t = do_T

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
            if self.debug:
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

        priv_view = self.args.view_key.encode('utf8')
        priv_spend = self.args.spend_key.encode('utf8')
        priv_view_key = crypto.b16_to_scalar(priv_view)
        priv_spend_key = crypto.b16_to_scalar(priv_spend)
        self.creds = monero.AccountCreds.new_wallet(priv_view_key, priv_spend_key, self.network_type)
        self.update_intro()

        logger.info('Address: %s' % self.creds.address.decode('utf8'))
        self.trez = trezor_lite.TrezorLite()
        self.trez.creds = self.creds
        self.trez.iface = self.trez_iface

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
        parser = argparse.ArgumentParser(description='Trezor wallet')

        parser.add_argument('--testnet', dest='testnet', default=False, action='store_const', const=True,
                            help='Testnet')

        parser.add_argument('--stagenet', dest='stagenet', default=False, action='store_const', const=True,
                            help='Testnet')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debug')

        parser.add_argument('--view-key', dest='view_key', required=True,
                            help='Hex coded private view key')

        parser.add_argument('--spend-key', dest='spend_key', required=True,
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


