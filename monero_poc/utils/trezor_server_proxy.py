#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

#
# Note pickling is used for message serialization.
# This is just for the prototyping & fast PoC, pickling wont be used in the production.
# Instead, protobuf messages will be defined and parsed to avoid malicious pickling.
#

import binascii
import logging
import pickle

import requests
from monero_glue import protobuf
from monero_glue.hwtoken import token
from monero_glue.protocol_base import messages
from monero_serialize import xmrserialize

logger = logging.getLogger(__name__)


class TokenProxy(token.TokenLite):
    """
    Trezor proxy calls to the remote server
    """

    def __init__(self, url=None, *args, **kwargs):
        super().__init__()
        self.url = "http://127.0.0.1:46123" if url is None else url
        self.endpoint = "%s/api/v1.0" % self.url

    async def transfer(self, method, cmd, payload):
        endp = "%s/%s" % (self.endpoint, method)
        req = {"cmd": cmd, "payload": payload}
        resp = requests.post(endp, json=req)
        resp.raise_for_status()
        return resp.json()

    async def transfer_pickle(self, method, action, *args, **kwargs):
        logger.debug("Action: %s" % action)
        to_pickle = (args, kwargs)
        pickled_data = pickle.dumps(to_pickle)
        payload = binascii.hexlify(pickled_data).decode("utf8")

        resp = await self.transfer(method, action, payload)
        pickle_data = binascii.unhexlify(resp["payload"].encode("utf8"))
        logger.debug(
            "Req size: %s, response size: %s" % (len(pickled_data), len(pickle_data))
        )

        res = pickle.loads(pickle_data)
        return res

    async def transfer_protobuf(self, method, msg: protobuf.MessageType):
        logger.debug("Method: %s" % method)
        writer = xmrserialize.MemoryReaderWriter()

        await protobuf.dump_message(writer, msg)
        proto_bin = bytes(writer.get_buffer())
        payload = {
            "msg_type": messages.get_message_type(msg),
            "msg": binascii.hexlify(proto_bin).decode("utf8"),
        }

        resp = await self.transfer(method, "", payload)
        resp_bin = binascii.unhexlify(resp["payload"]["msg"].encode("utf8"))
        logger.debug(
            "Req size: %s, response size: %s" % (len(proto_bin), len(resp_bin))
        )

        reader = xmrserialize.MemoryReaderWriter(bytearray(resp_bin))
        res = await protobuf.load_message(
            reader, messages.get_message_from_type(resp["payload"]["msg_type"])
        )
        return res

    async def call(self, msg, recode=True):
        return await self.transfer_protobuf("call", msg)

    async def call_in_session(self, msg, recode=True):
        return await self.transfer_protobuf("call", msg)

    async def ping(self, message=None, **kwargs):
        resp = requests.get("%s/ping" % self.endpoint)
        resp.raise_for_status()
        return resp.json()

    async def get_view_key(self, msg):
        return await self.transfer_protobuf("watch_only", msg)

    async def tsx_sign(self, msg):
        return await self.transfer_protobuf("tx_sign", msg)

    async def key_image_sync(self, msg, *args, **kwargs):
        return await self.transfer_protobuf("ki_sync", msg)
