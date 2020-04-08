#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import argparse
import os

from trezorlib import debuglink, device, ui
from trezorlib.client import TrezorClient
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.transport import get_transport


def main():
    parser = argparse.ArgumentParser(description="Trezor initializer")

    parser.add_argument(
        "--trezor-path", dest="trezor_path", default=None, help="Trezor device path"
    )
    parser.add_argument(
        "--trezor-idx", dest="trezor_idx", default=None, help="Trezor path idx"
    )
    parser.add_argument(
        "--mnemonic-idx", dest="mnemonic_idx", default=0, type=int, help="Trezor mnemonic index (testing indices)"
    )
    parser.add_argument(
        "--mnemonic", dest="mnemonic", default=None, help="Trezor mnemonic"
    )
    parser.add_argument(
        "--pin", dest="pin", default="", help="Trezor PIN protection"
    )
    parser.add_argument(
        "--label", dest="label", default="", help="Trezor label - on display"
    )
    parser.add_argument(
        "--language", dest="language", default="english", help="Seed language"
    )
    parser.add_argument(
        "--passphrase", dest="passphrase", default=False, action="store_const", const=True, help="Enable passphrase",
    )
    parser.add_argument(
        "--debug", dest="debug", default=False, action="store_const", const=True, help="Debug",
    )
    args = parser.parse_args()

    mnemonic12 = (
        "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
    )
    mnemonic24 = (
        "permit universe parent weapon amused modify essay borrow tobacco budget walnut "
        "lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple"
    )

    debug_mode = args.debug
    if args.trezor_path:
        path = args.trezor_path
    elif args.trezor_idx:
        path = "bridge:web01" if args.trezor_idx == "usb" else "udp:127.0.0.1:21324"
    else:
        path = os.environ.get("TREZOR_PATH", "bridge:web01")

    mnemonic = mnemonic24 if args.mnemonic_idx == 1 else mnemonic12
    if args.mnemonic:
        mnemonic = mnemonic

    wirelink = get_transport(path)
    client = (
        TrezorClientDebugLink(wirelink)
        if debug_mode
        else TrezorClient(wirelink, ui=ui.ClickUI())
    )
    #client.transport.session_begin()

    device.wipe(client)
    debuglink.load_device_by_mnemonic(
        client=client,
        mnemonic=mnemonic,
        pin=args.pin,
        passphrase_protection=args.passphrase,
        label=args.label,
        language=args.language,
    )

    #client.transport.session_end()
    client.close()


if __name__ == "__main__":
    main()
