#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import argparse
import asyncio
import binascii
import logging

import coloredlogs

from monero_glue.misc.bip import bip32
from monero_glue.misc.bip import bip39
from monero_glue.misc.bip import bip39_deriv
from monero_glue.xmr import crypto, monero
from monero_glue.xmr.core import mnemonic
from monero_glue.xmr.sub.addr import encode_addr
from monero_glue.xmr.sub.seed import SeedDerivation
from monero_glue.xmr.sub.xmr_net import NetworkTypes, net_version

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.WARNING, use_chroot=False)


parser = argparse.ArgumentParser(description="Monero seed utility")
parser.add_argument('input', metavar='mnemonics', nargs='*',
                    help='Input')

parser.add_argument("--seed", dest="seed", default=False, action="store_const", const=True,
                    help="Input is hexcoded seed / master secret, input to Hnode derivation")

parser.add_argument("--wlist-seed", dest="wlist_seed", default=False, action="store_const", const=True,
                    help="Mnemonics converted to seed using the wordlist indices")

parser.add_argument("--subs-test", dest="subs_test", default=False, action="store_const", const=True,
                    help="Compute 5x5 sub addresses on testnet")

parser.add_argument("--debug", dest="debug", default=False, action="store_const", const=True,
                    help="Debug",)

args = parser.parse_args()


async def amain(args):
    mnems = []
    for w in args.input:
        mnems += w.split(' ')
    mnems = [x.strip().lower() for x in mnems]

    if args.seed:
        seed = binascii.unhexlify(' '.join(mnems))
        sd = SeedDerivation.from_master_seed(seed)

    else:
        sd = SeedDerivation.from_mnemonics(mnems, args.wlist_seed)

    main_addr = sd.creds(network_type=NetworkTypes.MAINNET)
    test_addr = sd.creds(network_type=NetworkTypes.TESTNET)
    stage_addr = sd.creds(network_type=NetworkTypes.STAGENET)

    print("Seed bip39 words: %s" % " ".join(mnems))
    print("Seed bip32 b58:   %s\n" % binascii.hexlify(sd.master_seed).decode("ascii"))

    print("Seed Monero:      %s" % binascii.hexlify(sd.hashed).decode("ascii"))
    print("Seed Monero wrds: %s\n" % sd.electrum_words)

    print("Private spend key: %s" % binascii.hexlify(crypto.encodeint(sd.spend_sec)).decode("ascii"))
    print("Private view key:  %s\n" % binascii.hexlify(crypto.encodeint(sd.view_sec)).decode("ascii"))

    print("Public spend key:  %s" % binascii.hexlify(crypto.encodepoint(sd.spend_pub)).decode("ascii"))
    print("Public view key:   %s\n" % binascii.hexlify(crypto.encodepoint(sd.view_pub)).decode("ascii"))

    print("Mainnet Address:   %s" % main_addr.address.decode("ascii"))
    print("Testnet Address:   %s" % test_addr.address.decode("ascii"))
    print("Stagenet Address:  %s" % stage_addr.address.decode("ascii"))

    if args.subs_test:
        net_type = NetworkTypes.TESTNET

        for major in range(5):
            for minor in range(5):
                if major == 0 and minor == 0:
                    continue

                D, C = monero.generate_sub_address_keys(sd.view_sec, sd.spend_pub, major, minor)
                addr = encode_addr(
                    net_version(net_type, is_subaddr=True),
                    crypto.encodepoint(D),
                    crypto.encodepoint(C),
                )
                print(' %d,%d: %s' % (major, minor, addr))


def main(args):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain(args))
    loop.close()


if __name__ == "__main__":
    main(args)
