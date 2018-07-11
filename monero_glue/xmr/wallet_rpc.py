#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

#
# Note pickling is used for message serialization.
# This is just for the prototyping & fast PoC, pickling wont be used in the production.
# Instead, protobuf messages will be defined and parsed to avoid malicious pickling.
#

import logging
import os

import requests
from requests.auth import HTTPDigestAuth

logger = logging.getLogger(__name__)


class WalletRpc(object):
    """
    RPC helper
    """

    def __init__(self, agent, port=None, creds=None):
        self.agent = agent
        self.port = port
        self.creds = creds
        self.url = None
        self.set_addr("127.0.0.1:%s" % port)

    def set_addr(self, addr):
        self.url = "http://%s/json_rpc" % addr

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

    def balance(self):
        return self.request("getbalance")

    def height(self):
        return self.request("getheight")

    def get_transfers(self, params=None):
        return self.request("get_transfers", params)

    def rescan_bc(self):
        return self.request("rescan_blockchain")

    def transfer(self, params):
        return self.request("transfer", params)

    def submit_transfer(self, params):
        return self.request("submit_transfer", params)

    def stop_wallet(self):
        return self.request("stop_wallet")

    def export_outputs(self):
        return self.request("export_outputs")

    def import_outputs(self, params=None):
        return self.request("import_outputs", params)

    def import_key_images(self, params=None):
        return self.request("import_key_images", params)

    def refresh(self, params=None):
        return self.request("refresh", params)
