#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import traceback

from monero_glue.hwtoken import iface, misc
from monero_glue.xmr import monero
from monero_glue.protocol.key_image_sync import KeyImageSync
from monero_glue.protocol.tsx_sign import TsxSigner
from monero_glue.messages import MoneroKeyImageSync, MoneroTsxSign, MoneroRespError


class TokenLite(object):
    """
    Main Trezor object.
    Provides interface to the host, packages messages.
    """
    def __init__(self):
        self.tsx_ctr = 0
        self.err_ctr = 0
        self.tsx_obj = None  # type: TsxSigner
        self.ki_sync = None  # type: KeyImageSync
        self.creds = None  # type: monero.AccountCreds
        self.iface = iface.TokenInterface()
        self.debug = True

    async def ki_exc_handler(self, e):
        """
        Handles the exception thrown in the Trezor processing.

        :param e:
        :return:
        """
        if self.debug:
            traceback.print_exc()

        self.err_ctr += 1
        self.ki_sync = None  # clear transaction object
        await self.iface.transaction_error(e)

    async def tsx_exc_handler(self, e):
        """
        Handles the exception thrown in the Trezor processing. Clears transaction state.
        We could use decorator/wrapper for message calls but not sure how uPython handles them
        so now are entry points wrapped in try-catch.

        :param e:
        :return:
        """
        if self.debug:
            traceback.print_exc()

        self.err_ctr += 1
        self.tsx_obj = None  # clear transaction object
        await self.iface.transaction_error(e)

    async def monero_get_creds(self, address_n=None, network_type=None):
        """

        :param network_type:
        :return:
        """
        return self.creds

    def get_iface(self):
        """

        :return:
        """
        return self.iface

    async def test_pb_msg(self, msg):
        """
        Test message serialization
        :return:
        """
        if not __debug__:
            return

        pb = await misc.dump_pb_msg(msg)
        await misc.parse_pb_msg(pb, msg.__class__)

    async def tsx_sign(self, msg: MoneroTsxSign):
        if self.tsx_obj is None or msg.init:
            self.tsx_obj = TsxSigner(ctx=self, iface=self.iface, creds=self.creds)

        try:
            await self.test_pb_msg(msg)

            res = await self.tsx_obj.sign(self, msg)
            if await self.tsx_obj.should_purge():
                self.tsx_obj = None

            await self.test_pb_msg(res)
            return res

        except Exception as e:
            await self.tsx_exc_handler(e)
            self.tsx_obj = None
            return MoneroRespError(exc=e)

    async def key_image_sync(self, msg: MoneroKeyImageSync):
        try:
            if msg.init:
                self.ki_sync = KeyImageSync(ctx=self, iface=self.iface, creds=self.creds)
                return await self.ki_sync.init(self, msg.init)

            elif msg.step:
                return await self.ki_sync.sync(self, msg.step)

            elif msg.final_msg:
                res = await self.ki_sync.final(self, msg.final_msg)
                self.ki_sync = None
                return res

            else:
                raise ValueError('Unknown error')

        except Exception as e:
            await self.ki_exc_handler(e)
            self.ki_sync = None
            return MoneroRespError(exc=e)
