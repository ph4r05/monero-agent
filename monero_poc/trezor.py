#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import sys
import argparse
import binascii
import logging
import coloredlogs
from blessed import Terminal
from cmd2 import Cmd

from monero_glue import crypto, monero


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


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
        self.t = Terminal()

    def update_intro(self):
        """
        Updates intro text for CLI header - adds version to it.
        :return:
        """
        self.intro = '-'*self.get_term_width() + \
                     '\n    Trezor server\n' + \
                     ('\n    Address: %s ' % self.creds.address.decode('utf8')) + \
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
        self.cmdloop()

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


