#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import sys
import os
import argparse
import binascii
import logging
import traceback
import threading
import coloredlogs
from blessed import Terminal
from cmd2 import Cmd

import eventlet
from eventlet import wsgi
from flask import Flask, jsonify, request, abort

from monero_glue import crypto, monero


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)
eventlet.monkey_patch(socket=True)


class TrezorServer(Cmd):
    """
    Trezor emulator server
    """
    prompt = '$> '

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.args = None
        self.network_type = None
        self.creds = None
        self.port = 46123
        self.t = Terminal()

        self.running = True
        self.stop_event = threading.Event()
        self.local_data = threading.local()
        self.thread_rest = None

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

    def init_rest(self):
        """
        Initializes rest server
        :return:
        """

        @self.flask.route('/api/v1.0/ping', methods=['GET'])
        def keep_alive():
            return self.on_ping(request=request)

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

    def on_ping(self, request=None):
        """
        Simple ping
        :param request:
        :return:
        """
        return jsonify({'result': True})



    #
    # Work
    #

    def rest_thread_work(self):
        """
        Main work method for the server - accepting incoming connections.
        :return:
        """
        logger.info('REST thread started %s %s %s dbg: %s'
                    % (os.getpid(), os.getppid(), threading.current_thread(), self.debug))
        try:
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

    def entry(self):
        """
        pass
        :return:
        """
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

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

        print('Address: %s' % self.creds.address.decode('utf8'))

        self.rest_server_boot()
        self.cmdloop()
        self.terminating()

    def main(self):
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
        self.entry()
        sys.argv = args_src


def main():
    agent = TrezorServer()
    agent.main()


if __name__ == '__main__':
    main()


