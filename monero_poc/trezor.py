#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import argparse
import binascii
from monero_glue import crypto, monero


class TrezorServer(object):
    """
    Trezor emulator server
    """

    def __init__(self):
        self.args = None
        self.network_type = None
        self.creds = None

    def entry(self):
        """
        pass
        :return:
        """
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

        print('Address: %s' % self.creds.address.decode('utf8'))

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

        parser.add_argument('--view-key', dest='view_key', required=True,
                            help='Hex coded private view key')

        parser.add_argument('--spend-key', dest='spend_key', required=True,
                            help='Hex coded private spend key')

        self.args = parser.parse_args()
        self.entry()


def main():
    agent = TrezorServer()
    agent.main()


if __name__ == '__main__':
    main()


