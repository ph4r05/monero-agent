#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import traceback

from monero_glue.hwtoken import iface, misc
from monero_glue.messages import (
    DebugMoneroDiagAck,
    Failure,
    FailureType,
    MoneroGetWatchKey,
    MoneroKeyImageSyncRequest,
    MoneroTransactionSignRequest,
    MoneroWatchKey,
)
from monero_glue.protocol.key_image_sync import KeyImageSync
from monero_glue.protocol.tsx_sign import TsxSigner
from monero_glue.protocol_base.error import exc2str
from monero_glue.xmr import crypto, monero


class TokenLite(object):
    """
    Main Trezor object.
    Provides interface to the host, packages messages.
    """

    def __init__(self):
        self.tsx_ctr = 0
        self.err_ctr = 0
        self.tsx_obj = None  # type: TsxSigner
        self.tsx_state = None
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

    async def call(self, msg, recode=True):
        return Failure(code=FailureType.FirmwareError, message="unsupported")

    async def call_in_session(self, msg, recode=True):
        return Failure(code=FailureType.FirmwareError, message="unsupported")

    async def ping(self, message=None, **kwargs):
        return DebugMoneroDiagAck()

    async def get_view_key(self, msg: MoneroGetWatchKey):
        if msg.network_type != self.creds.network_type:
            return Failure(message="InvalidNetworkType")

        return MoneroWatchKey(
            watch_key=crypto.encodepoint(self.creds.view_key_private),
            address=self.creds.address,
        )

    async def tsx_sign(self, msg: MoneroTransactionSignRequest):
        try:
            await self.test_pb_msg(msg)

            signer = TsxSigner()
            await signer.wake_up(self, self.tsx_state, msg, iface=self.iface)
            self.tsx_state = None

            res = await signer.sign(msg)
            if not await signer.should_purge():
                self.tsx_state = await signer.state_save()

            await self.test_pb_msg(res)
            return res

        except Exception as e:
            await self.tsx_exc_handler(e)
            self.tsx_obj = None
            return Failure(message=exc2str(e))

    async def key_image_sync(self, msg: MoneroKeyImageSyncRequest):
        try:
            if msg.init:
                self.ki_sync = KeyImageSync(
                    ctx=self, iface=self.iface, creds=self.creds
                )
                return await self.ki_sync.init(self, msg.init)

            elif msg.step:
                return await self.ki_sync.sync(self, msg.step)

            elif msg.final_msg:
                res = await self.ki_sync.final(self, msg.final_msg)
                self.ki_sync = None
                return res

            else:
                raise ValueError("Unknown error")

        except Exception as e:
            await self.ki_exc_handler(e)
            self.ki_sync = None
            return Failure(message=exc2str(e))
