#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import argparse
import binascii
from monero_glue.xmr import monero, crypto


def main():
    """
    Entry point
    :return:
    """
    parser = argparse.ArgumentParser(description='Generate non-deterministic wallet credentials')

    parser.add_argument('--testnet', dest='testnet', default=False, action='store_const', const=True,
                        help='Testnet')

    parser.add_argument('--stagenet', dest='stagenet', default=False, action='store_const', const=True,
                        help='Testnet')

    args = parser.parse_args()

    network_type = monero.NetworkTypes.MAINNET
    if args.testnet:
        network_type = monero.NetworkTypes.TESTNET
    elif args.stagenet:
        network_type = monero.NetworkTypes.STAGENET

    priv_view = crypto.random_scalar()
    priv_spend = crypto.random_scalar()
    w = monero.AccountCreds.new_wallet(priv_view, priv_spend, network_type=network_type)

    print('Address: %s' % w.address.decode('utf8'))
    print('Private view key:  %s' % binascii.hexlify(crypto.encodeint(priv_view)).decode('utf8'))
    print('Private spend key: %s' % binascii.hexlify(crypto.encodeint(priv_spend)).decode('utf8'))


if __name__ == '__main__':
    main()


