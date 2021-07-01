#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import argparse
import os
import sys
import asyncio
import logging

from monero_glue.trezor import manager as tmanager
from monero_glue.xmr.sub.xmr_net import NetworkTypes
from monero_glue.agent import agent_lite
from trezorlib import debuglink, device, ui
from trezorlib.client import TrezorClient
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.transport import get_transport


logger = logging.getLogger(__name__)
try:
    import coloredlogs
    coloredlogs.CHROOT_FILES = []
    coloredlogs.install(level=logging.WARNING, use_chroot=False)
except:
    pass


async def amain():
    parser = argparse.ArgumentParser(description="Trezor address loader")

    parser.add_argument(
        "--trezor-path", dest="trezor_path", default=None, help="Trezor device path"
    )
    parser.add_argument(
        "--trezor-idx", dest="trezor_idx", default=None, help="Trezor path idx"
    )
    parser.add_argument(
        "--pin", dest="pin", default="", help="Trezor PIN protection"
    )
    parser.add_argument(
        "--passphrase", dest="passphrase", default=False, action="store_const", const=True, help="Enable passphrase",
    )
    parser.add_argument(
        "--debug", dest="debug", default=False, action="store_const", const=True, help="Debug",
    )
    parser.add_argument(
        "--debug-link", dest="debug_link", default=False, action="store_const", const=True,
        help="Debug link with Trezor. May skip some dialogs (e.g., passphrase entry)",
    )
    args = parser.parse_args()

    try:
        if args.debug:
            coloredlogs.install(level=logging.DEBUG, use_chroot=False)
        else:
            coloredlogs.install(level=logging.INFO, use_chroot=False)
    except Exception as e:
        pass

    debug_mode = args.debug_link
    if args.trezor_path:
        path = args.trezor_path
    elif args.trezor_idx:
        path = "bridge:web01" if args.trezor_idx == "usb" else "udp:127.0.0.1:21324"
    else:
        path = os.environ.get("TREZOR_PATH", "bridge:web01")

    wirelink = get_transport(path)
    client = (
        TrezorClientDebugLink(wirelink)
        if debug_mode
        else TrezorClient(wirelink, ui=ui.ClickUI())
    )

    # client.transport.session_begin()
    trezor_proxy = tmanager.Trezor(path=path, debug=args.debug_link)
    network_type = NetworkTypes.MAINNET
    agent = agent_lite.Agent(trezor_proxy, network_type=network_type)
    res = await agent.get_address()
    print(res)

    # client.transport.session_end()
    client.close()
    sys.exit(0)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain())
    # loop.run_forever()
    loop.close()


if __name__ == "__main__":
    main()
