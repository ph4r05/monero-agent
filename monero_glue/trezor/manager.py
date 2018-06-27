#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import os
from trezorlib import coins
from trezorlib import tx_api
from trezorlib.client import TrezorClientDebugLink, TrezorClient
from trezorlib.transport import get_transport
from trezorlib.tools import parse_path
from trezorlib import monero, protobuf
from trezorlib import messages as proto

from monero_serialize import xmrserialize
from monero_glue.hwtoken import token, misc
from monero_glue.messages import MoneroExportedKeyImage, \
    MoneroKeyImageExportInit, MoneroKeyImageExportInitResp, \
    MoneroKeyImageSyncStep, MoneroKeyImageSyncStepResp, \
    MoneroKeyImageSyncFinalResp, \
    MoneroGetWatchKey, MoneroGetAddress, \
    MoneroRespError




class TrezorSession(object):
    def __init__(self, client, **kwargs):
        self.client = client

    def __enter__(self):
        self.client.transport.session_begin()
        return self.client

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client.transport.session_end()


class Trezor(token.TokenLite):
    """
    Trezor proxy calls to the trezor
    """
    def __init__(self, path=None, debug=False, address_n=None, network_type=0, *args, **kwargs):
        super().__init__()
        if path is None:
            path = os.environ.get('TREZOR_PATH', 'udp:127.0.0.1:21324')

        self.debug = debug
        self.wirelink = get_transport(path)
        self.client = TrezorClientDebugLink(self.wirelink) if debug else TrezorClient(self.wirelink)

        if debug:
            self.debuglink = self.wirelink.find_debug()
            self.client.set_debuglink(self.debuglink)

        self.address_n = address_n if address_n else parse_path(monero.DEFAULT_BIP32_PATH)
        self.network_type = network_type

    def close(self):
        self.client.close()

    def session(self):
        return TrezorSession(self.client)

    async def ping(self, message=None, **kwargs):
        with self.session():
            return self.client.ping(message if message else 'monero', **kwargs)

    async def watch_only(self):
        with self.session():
            msg = MoneroGetWatchKey(address_n=self.address_n, network_type=self.network_type)
            res = self.client.call(msg)
            return res

    async def tsx_sign(self, msg):
        with self.session():
            return self.client.call(msg)

    async def key_image_sync(self, msg, *args, **kwargs):
        with self.session():
            return self.client.call(msg)


