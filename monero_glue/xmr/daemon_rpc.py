#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import logging

import requests
from monero_serialize import xmrserialize, xmrrpc
from requests.auth import HTTPDigestAuth

logger = logging.getLogger(__name__)


class AutoModeler(object):
    def __init__(self):
        pass

    def to_model(self, obj):
        if isinstance(obj, xmrrpc.IModel):
            return obj
        if isinstance(obj, int):
            return xmrrpc.IntegerModel(obj)


class DaemonRpc(object):
    """
    Daemon RPC helper
    """

    def __init__(self, port=28081, creds=None):
        self.port = port
        self.creds = creds
        self.url = None
        self.base_url = None
        self.set_addr("127.0.0.1:%s" % port)

    def set_addr(self, addr):
        self.base_url = "http://%s" % addr
        self.url = "%s/json_rpc" % self.base_url

    def set_creds(self, creds):
        if creds is None or (isinstance(creds, (list, tuple)) and len(creds) == 2):
            self.creds = creds
        elif isinstance(creds, str):
            self.creds = creds.split(":", 1)
        else:
            raise ValueError("Unknown creds type")

    def request(self, method, params=None):
        """
        Request wrapper
        {"jsonrpc":"2.0","id":"0","method":"get_address", "params":{"account_index": 0, "address_index": [0,1,2,3,4,5]}
        :param method:
        :param params:
        :return:
        """
        auth = HTTPDigestAuth(self.creds[0], self.creds[1]) if self.creds else None
        js = {"jsonrpc": "2.0", "id": "0", "method": method}
        if params:
            js["params"] = params

        resp = requests.post(self.url, json=js, auth=auth)
        resp.raise_for_status()
        return resp.json()

    def request_bin(self, method, data=None):
        auth = HTTPDigestAuth(self.creds[0], self.creds[1]) if self.creds else None
        resp = requests.post("%s/%s" % (self.base_url, method), data=data, auth=auth)
        return resp.content

    async def dump_bin(self, msg):
        writer = xmrserialize.MemoryReaderWriter()
        ar = xmrrpc.Archive(writer, True)

        await ar.root()
        await ar.section(msg)
        return writer.get_buffer()

    async def load_bin(self, data):
        reader = xmrserialize.MemoryReaderWriter(bytearray(data))
        ar = xmrrpc.Archive(reader, False)

        msg = {}
        await ar.root()
        await ar.section(msg)
        return msg

    async def get_version(self):
        return self.request("get_version")["result"]

    async def get_info(self):
        return self.request("get_info")["result"]

    async def get_blocks_by_height(self, heights):
        req = {
            "heights": xmrrpc.ArrayModel(
                heights, xmrrpc.SerializeType.UINT64 | xmrrpc.SerializeType.ARRAY_FLAG
            )
        }
        req_bin = await self.dump_bin(req)

        resp_bin = self.request_bin("getblocks_by_height.bin", req_bin)
        resp = await self.load_bin(resp_bin)
        return resp
