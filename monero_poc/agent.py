#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
import asyncio
import argparse
import binascii
import logging
import json
import requests
import coloredlogs

from monero_glue import crypto, monero, agent_lite, trezor_lite, wallet
from monero_glue.monero import TsxData
from monero_serialize import xmrboost, xmrtypes, xmrserialize, xmrobj, xmrjson

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.DEBUG, use_chroot=False)


class HostAgent(object):
    """
    Host agent wrapper
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = None

        self.network_type = None
        self.address = None
        self.priv_view = None
        self.pub_view = None
        self.pub_spend = None

        self.loop = asyncio.get_event_loop()

    async def entry(self):
        """
        pass
        :return:
        """
        priv_view = self.args.view_key.encode('utf8')
        self.priv_view = crypto.b16_to_scalar(priv_view)
        self.address = self.args.address.encode('utf8')
        self.pub_view = crypto.scalarmult_base(self.priv_view)

        version, pub_spend, pub_view = monero.decode_addr(self.address)
        self.pub_spend = crypto.decodepoint(pub_spend)

        if not crypto.point_eq(self.pub_view, crypto.decodepoint(pub_view)):
            raise ValueError('Computed view public key does not match the one from address')

        print('Ver: %s' % version)
        print('Public spend key: %s' % binascii.hexlify(pub_spend).decode('utf8'))
        print('Public view key : %s' % binascii.hexlify(pub_view).decode('utf8'))

        logger.info('Terminating')

    async def main(self):
        """
        Entry point
        :return:
        """
        parser = argparse.ArgumentParser(description='Trezor CLI based host client')

        parser.add_argument('--address', dest='address', required=True,
                            help='Full address')

        parser.add_argument('--view-key', dest='view_key', required=True,
                            help='Hex coded private view key')

        self.args = parser.parse_args()
        await self.entry()


async def main():
    agent = HostAgent()
    await agent.main()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    # loop.run_forever()
    loop.close()


