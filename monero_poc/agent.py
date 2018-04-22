#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import argparse
import binascii
import logging
import coloredlogs

from monero_glue import crypto, monero


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class HostAgent(object):
    """
    Host agent wrapper
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = None
        self.network_type = None

    def entry(self):
        """
        pass
        :return:
        """
        priv_view = self.args.view_key.encode('utf8')
        priv_view_key = crypto.b16_to_scalar(priv_view)
        pub_view_comp = crypto.scalarmult_base(priv_view_key)

        version, pub_spend, pub_view = monero.decode_addr(self.args.address.encode('utf8'))
        if not crypto.point_eq(pub_view_comp, crypto.decodepoint(pub_view)):
            raise ValueError('Computed view public key does not match the one from address')

        print('Ver: %s' % version)
        print('Public spend key: %s' % binascii.hexlify(pub_spend).decode('utf8'))
        print('Public view key : %s' % binascii.hexlify(pub_view).decode('utf8'))

    def main(self):
        """
        Entry point
        :return:
        """
        parser = argparse.ArgumentParser(description='Trezor CLI based host client')

        parser.add_argument('--address', dest='address', required=True,
                            help='Full address')

        parser.add_argument('--view-key', dest='view_key', required=True,
                            help='Hex coded private view key')

        self.args = parser.parse_args()
        self.entry()


def main():
    agent = HostAgent()
    agent.main()


if __name__ == '__main__':
    main()


