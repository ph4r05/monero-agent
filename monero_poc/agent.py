#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

#
# Note pickling is used for message serialization.
# This is just for the prototyping & fast PoC, pickling wont be used in the production.
# Instead, protobuf messages will be defined and parsed to avoid malicious pickling.
#

import os
import asyncio
import argparse
import binascii
import logging
import json
import requests
import coloredlogs
import pickle

from monero_glue import crypto, monero, agent_lite, trezor_lite, wallet
from monero_glue.monero import TsxData
from monero_serialize import xmrboost, xmrtypes, xmrserialize, xmrobj, xmrjson

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.DEBUG, use_chroot=False)


class TrezorProxy(trezor_lite.TrezorLite):
    """
    Trezor proxy calls to the remote server
    """
    def __init__(self, url=None, *args, **kwargs):
        super().__init__()
        self.url = 'http://127.0.0.1:46123' if url is None else url
        self.endpoint = '%s/api/v1.0' % self.url

    async def transfer(self, cmd, payload):
        endp = '%s/tx_sign' % self.endpoint
        req = {'cmd': cmd, 'payload': payload}
        resp = requests.post(endp, json=req)
        return resp.json()

    async def transfer_pickle(self, action, *args, **kwargs):
        logger.debug('Action: %s' % action)
        to_pickle = (args, kwargs)
        pickled_data = pickle.dumps(to_pickle)
        payload = binascii.hexlify(pickled_data).decode('utf8')

        resp = await self.transfer(action, payload)
        pickle_data = binascii.unhexlify(resp['payload'].encode('utf8'))
        logger.debug('Req size: %s, response size: %s' % (len(pickled_data), len(pickle_data)))

        res = pickle.loads(pickle_data)
        return res

    async def init_transaction(self, tsx_data: TsxData):
        return await self.transfer_pickle('init_transaction', tsx_data)

    async def set_tsx_input(self, src_entr):
        return await self.transfer_pickle('set_tsx_input', src_entr)

    async def tsx_inputs_permutation(self, permutation):
        return await self.transfer_pickle('tsx_inputs_permutation', permutation)

    async def tsx_input_vini(self, *args, **kwargs):
        return await self.transfer_pickle('tsx_input_vini', *args, **kwargs)

    async def set_tsx_output1(self, dst_entr, dst_entr_hmac):
        return await self.transfer_pickle('set_tsx_output1', dst_entr, dst_entr_hmac)

    async def all_out1_set(self):
        return await self.transfer_pickle('all_out1_set')

    async def tsx_mlsag_done(self):
        return await self.transfer_pickle('tsx_mlsag_done')

    async def sign_input(self, *args, **kwars):
        return await self.transfer_pickle('sign_input', *args, **kwars)


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
        self.trezor_proxy = TrezorProxy()
        self.agent = agent_lite.Agent(self.trezor_proxy)

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

        if self.args.sign:
            await self.sign(self.args.sign)

        logger.info('Terminating')

    async def sign(self, file):
        """
        Performs TX signature
        :param file:
        :return:
        """
        if not os.path.exists(file):
            raise ValueError('Could not find unsigned transaction file')

        data = None
        with open(file, 'rb') as fh:
            data = fh.read()

        msg = await wallet.load_unsigned_tx(self.priv_view, data)
        txes = await self.agent.sign_unsigned_tx(msg)
        print(txes)

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

        parser.add_argument('--sign', dest='sign', default=None,
                            help='Sign the unsigned file')

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


