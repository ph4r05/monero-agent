#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Install dependencies with `pip install .[poc,trezor]`


import argparse
import asyncio
import binascii
import logging

from monero_glue.misc.bip import bip32, bip39, bip39_deriv
from monero_glue.xmr import crypto, monero
from monero_glue.xmr.core import mnemonic
from monero_glue.xmr.sub.addr import encode_addr
from monero_glue.xmr.sub.seed import SeedDerivation
from monero_glue.xmr.sub.xmr_net import NetworkTypes, net_version


logger = logging.getLogger(__name__)
try:
    import coloredlogs
    coloredlogs.CHROOT_FILES = []
    coloredlogs.install(level=logging.WARNING, use_chroot=False)
except:
    pass


async def amain():
    parser = argparse.ArgumentParser(description="Monero seed utility")
    parser.add_argument("input", metavar="mnemonics", nargs="*", help="Input")

    parser.add_argument(
        "--seed",
        dest="seed",
        default=False,
        action="store_const",
        const=True,
        help="Input is hexcoded seed / master secret, input to Hnode derivation",
    )

    parser.add_argument(
        "--wlist-seed",
        dest="wlist_seed",
        default=False,
        action="store_const",
        const=True,
        help="Mnemonics converted to seed using the wordlist indices",
    )

    parser.add_argument(
        "--electrum-mnemonics",
        dest="electrum_mnemonics",
        default=False,
        action="store_const",
        const=True,
        help="Monero electrum mneomonics encoding Monero master secret seed",
    )

    parser.add_argument(
        "--monero-master",
        dest="monero_master",
        default=False,
        action="store_const",
        const=True,
        help="Monero master secret seed",
    )

    parser.add_argument(
        "--mainnet",
        dest="mainnet",
        default=False,
        action="store_const",
        const=True,
        help="Mainnet",
    )

    parser.add_argument(
        "--testnet",
        dest="testnet",
        default=False,
        action="store_const",
        const=True,
        help="Testnet",
    )

    parser.add_argument(
        "--stagenet",
        dest="stagenet",
        default=False,
        action="store_const",
        const=True,
        help="Stagenet",
    )

    parser.add_argument(
        "--subs",
        dest="subs",
        default=False,
        action="store_const",
        const=True,
        help="Compute 5x5 sub addresses given network",
    )

    parser.add_argument(
        "--slip0010",
        dest="slip0010",
        default=False,
        action="store_const",
        const=True,
        help="Use SLIP-0010 derivation with ED25519",
    )

    parser.add_argument("--path", dest="path", default=None, help="Custom derivation path")
    parser.add_argument("--passphrase", dest="passphrase", default="", help="Specify a passphrase for seed derivation")

    parser.add_argument(
        "--debug",
        dest="debug",
        default=False,
        action="store_const",
        const=True,
        help="Debug",
    )

    args = parser.parse_args()

    mnems = []
    for w in args.input:
        mnems += w.split(" ")
    mnems = [x.strip().lower() for x in mnems]

    bip44_derived = True
    deriv_args = {}
    if args.slip0010:
        deriv_args["slip0010"] = True
    if args.path:
        deriv_args["path"] = args.path

    if (
        sum([args.electrum_mnemonics, args.wlist_seed, args.monero_master, args.seed])
        > 1
    ):
        raise ValueError("Conflicting input options")

    if args.electrum_mnemonics:
        if args.slip0010 or args.path:
            raise ValueError(
                "--electrum-mnemonics is conflicting with --slip0010 and --path"
            )
        bip44_derived = False
        sd = SeedDerivation.from_monero_mnemonics(mnems)

    elif args.monero_master:
        if args.slip0010 or args.path:
            raise ValueError(
                "--monero-master is conflicting with --slip0010 and --path"
            )
        bip44_derived = False
        seed = binascii.unhexlify(" ".join(mnems))
        sd = SeedDerivation.from_monero_seed(seed)

    elif args.seed:
        seed = binascii.unhexlify(" ".join(mnems))
        sd = SeedDerivation.from_master_seed(seed, **deriv_args)

    else:
        sd = SeedDerivation.from_mnemonics(mnems, args.wlist_seed, args.passphrase.encode("utf8"), **deriv_args)

    main_addr = sd.creds(network_type=NetworkTypes.MAINNET)
    test_addr = sd.creds(network_type=NetworkTypes.TESTNET)
    stage_addr = sd.creds(network_type=NetworkTypes.STAGENET)

    if bip44_derived:
        print("Seed bip39 words: %s" % " ".join(mnems))
        print(
            "Seed bip32 b58:   %s\n" % binascii.hexlify(sd.master_seed).decode("ascii")
        )

    if sd.monero_master:
        print(
            "Seed Monero:      %s" % binascii.hexlify(sd.monero_master).decode("ascii")
        )
    if sd.electrum_words:
        print("Seed Monero wrds: %s\n" % sd.electrum_words)

    print(
        "Private spend key: %s"
        % binascii.hexlify(crypto.encodeint(sd.spend_sec)).decode("ascii")
    )
    print(
        "Private view key:  %s\n"
        % binascii.hexlify(crypto.encodeint(sd.view_sec)).decode("ascii")
    )

    print(
        "Public spend key:  %s"
        % binascii.hexlify(crypto.encodepoint(sd.spend_pub)).decode("ascii")
    )
    print(
        "Public view key:   %s\n"
        % binascii.hexlify(crypto.encodepoint(sd.view_pub)).decode("ascii")
    )

    print("Mainnet Address:   %s" % main_addr.address.decode("ascii"))
    print("Testnet Address:   %s" % test_addr.address.decode("ascii"))
    print("Stagenet Address:  %s" % stage_addr.address.decode("ascii"))

    if args.subs:
        if args.mainnet or (not args.testnet and not args.stagenet):
            print("Mainnet Sub addresses: ")
            print_sub_addresses(sd, NetworkTypes.MAINNET)
        if args.testnet:
            print("Testnet Sub addresses: ")
            print_sub_addresses(sd, NetworkTypes.TESTNET)
        if args.stagenet:
            print("Stagenet Sub addresses: ")
            print_sub_addresses(sd, NetworkTypes.STAGENET)


def print_sub_addresses(sd, net_type, major_max=5, minor_max=5):
    for major, minor, addr in gen_sub_address(sd, net_type, major_max, minor_max):
        print(" %d, %d: %s" % (major, minor, addr.decode("ascii")))


def gen_sub_address(sd, net_type, major_max, minor_max):
    for major in range(major_max):
        for minor in range(minor_max):
            if major == 0 and minor == 0:
                continue

            D, C = monero.generate_sub_address_keys(
                sd.view_sec, sd.spend_pub, major, minor
            )
            addr = encode_addr(
                net_version(net_type, is_subaddr=True),
                crypto.encodepoint(D),
                crypto.encodepoint(C),
            )
            yield major, minor, addr


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain())
    loop.close()


if __name__ == "__main__":
    main()
