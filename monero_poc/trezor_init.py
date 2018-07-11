#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import os
import argparse


from trezorlib import coins, tx_api
from trezorlib.client import TrezorClient, TrezorClientDebugLink
from trezorlib.transport import get_transport


parser = argparse.ArgumentParser(description="Trezor initializer")

parser.add_argument(
    "--trezor-path", dest="trezor_path", default=None, help="Trezor path"
)
parser.add_argument(
    "--trezor-idx", dest="trezor_idx", default=None, help="Trezor path idx"
)
parser.add_argument(
    "--mnemonic", dest="mnemonic", default=0, type=int, help="Trezor mnemonic"
)
parser.add_argument(
    "--debug",
    dest="debug",
    default=False,
    action="store_const",
    const=True,
    help="Debug",
)
args = parser.parse_args()

mnemonic12 = (
    "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
)
mnemonic24 = "permit universe parent weapon amused modify essay borrow tobacco budget walnut " "lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple"

debug_mode = args.debug
if args.trezor_path:
    path = args.trezor_path
elif args.trezor_idx:
    path = "bridge:web01" if args.trezor_idx == "usb" else "udp:127.0.0.1:21324"
else:
    path = os.environ.get("TREZOR_PATH", "bridge:web01")

mnemonic = mnemonic24 if args.mnemonic == 1 else mnemonic12


wirelink = get_transport(path)
client = TrezorClientDebugLink(wirelink) if debug_mode else TrezorClient(wirelink)
if debug_mode:
    debuglink = wirelink.find_debug()
    client.set_debuglink(debuglink)

client.transport.session_begin()

client.wipe_device()
client.load_device_by_mnemonic(
    mnemonic=mnemonic,
    pin="",
    passphrase_protection=False,
    label="ph4test",
    language="english",
)

client.transport.session_end()
client.close()
