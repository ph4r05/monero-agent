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
from monero_glue.xmr.sub.xmr_net import NetworkTypes

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

    else:
        if args.wlist_seed:
            indices = [bip39.english_words.index(x) for x in mnems]
            seed = bip32.Wallet.indices_to_bytes(indices)
        else:
            seed = bip39_deriv.mnemonics_to_seed(' '.join(mnems))

    seed_bip32_b58 = binascii.hexlify(seed)
    wl = bip32.Wallet.from_master_secret(seed)

    # Generate private keys based on the gen mechanism. Bip44 path + Monero backward compatible
    data = wl.get_child_for_path("m/44'/128'/0'/0/0")
    to_hash = binascii.unhexlify(data.private_key.get_key())

    # to_hash is initial seed in the Monero sense, recoverable from this seed
    hashed = crypto.cn_fast_hash(to_hash)
    electrum_words = " ".join(mnemonic.mn_encode(hashed))

    keys = monero.generate_monero_keys(hashed)
    spend_sec, spend_pub, view_sec, view_pub = keys

    main_addr = monero.AccountCreds.new_wallet(
        priv_view_key=view_sec, priv_spend_key=spend_sec, network_type=NetworkTypes.MAINNET)
    test_addr = monero.AccountCreds.new_wallet(
        priv_view_key=view_sec, priv_spend_key=spend_sec, network_type=NetworkTypes.TESTNET)
    stage_addr = monero.AccountCreds.new_wallet(
        priv_view_key=view_sec, priv_spend_key=spend_sec, network_type=NetworkTypes.STAGENET)

    print("Seed bip39 words: %s" % " ".join(mnems))
    print("Seed bip32 b58:   %s\n" % seed_bip32_b58.decode("ascii"))

    print("Seed Monero:      %s" % binascii.hexlify(hashed).decode("ascii"))
    print("Seed Monero wrds: %s\n" % electrum_words)

    print("Private spend key: %s" % binascii.hexlify(crypto.encodeint(spend_sec)).decode("ascii"))
    print("Private view key:  %s\n" % binascii.hexlify(crypto.encodeint(view_sec)).decode("ascii"))

    print("Public spend key:  %s" % binascii.hexlify(crypto.encodepoint(spend_pub)).decode("ascii"))
    print("Public view key:   %s\n" % binascii.hexlify(crypto.encodepoint(view_pub)).decode("ascii"))

    print("Mainnet Address:   %s" % main_addr.address.decode("ascii"))
    print("Testnet Address:   %s" % test_addr.address.decode("ascii"))
    print("Stagenet Address:  %s" % stage_addr.address.decode("ascii"))


def main(args):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain(args))
    loop.close()


if __name__ == "__main__":
    main(args)
