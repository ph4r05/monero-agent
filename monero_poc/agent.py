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
import requests
import coloredlogs
import pickle
import sys

from . import trace_logger
from monero_glue import agent_lite, agent_misc, trezor_lite
from monero_glue.xmr import wallet, monero, crypto
from monero_glue.xmr.monero import TsxData
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.WARNING, use_chroot=False)


class TrezorProxy(trezor_lite.TrezorLite):
    """
    Trezor proxy calls to the remote server
    """
    def __init__(self, url=None, *args, **kwargs):
        super().__init__()
        self.url = 'http://127.0.0.1:46123' if url is None else url
        self.endpoint = '%s/api/v1.0' % self.url

    async def ping(self):
        resp = requests.get('%s/ping' % self.endpoint)
        return resp.json()

    async def transfer(self, method, cmd, payload):
        endp = '%s/%s' % (self.endpoint, method)
        req = {'cmd': cmd, 'payload': payload}
        resp = requests.post(endp, json=req)
        resp.raise_for_status()
        return resp.json()

    async def transfer_pickle(self, method, action, *args, **kwargs):
        logger.debug('Action: %s' % action)
        to_pickle = (args, kwargs)
        pickled_data = pickle.dumps(to_pickle)
        payload = binascii.hexlify(pickled_data).decode('utf8')

        resp = await self.transfer(method, action, payload)
        pickle_data = binascii.unhexlify(resp['payload'].encode('utf8'))
        logger.debug('Req size: %s, response size: %s' % (len(pickled_data), len(pickle_data)))

        res = pickle.loads(pickle_data)
        return res

    async def init_transaction(self, tsx_data: TsxData):
        return await self.transfer_pickle('tx_sign', 'init_transaction', tsx_data)

    async def set_tsx_input(self, src_entr):
        return await self.transfer_pickle('tx_sign', 'set_tsx_input', src_entr)

    async def tsx_inputs_permutation(self, permutation):
        return await self.transfer_pickle('tx_sign', 'tsx_inputs_permutation', permutation)

    async def tsx_input_vini(self, *args, **kwargs):
        return await self.transfer_pickle('tx_sign', 'tsx_input_vini', *args, **kwargs)

    async def set_tsx_output1(self, dst_entr, dst_entr_hmac):
        return await self.transfer_pickle('tx_sign', 'set_tsx_output1', dst_entr, dst_entr_hmac)

    async def all_out1_set(self):
        return await self.transfer_pickle('tx_sign', 'all_out1_set')

    async def tsx_mlsag_done(self):
        return await self.transfer_pickle('tx_sign', 'tsx_mlsag_done')

    async def sign_input(self, *args, **kwargs):
        return await self.transfer_pickle('tx_sign', 'sign_input', *args, **kwargs)

    async def tx_sign_final(self, *args, **kwargs):
        return await self.transfer_pickle('tx_sign', 'final', *args, **kwargs)


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

        self.trace_logger = trace_logger.Tracelogger(logger)
        self.loop = asyncio.get_event_loop()
        self.trezor_proxy = TrezorProxy()
        self.agent = agent_lite.Agent(self.trezor_proxy)

    async def entry(self):
        """
        pass
        :return:
        """
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG, use_chroot=False)

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
            try:
                return await self.sign(self.args.sign)

            except agent_misc.TrezorReturnedError as e:
                self.trace_logger.log(e)
                print('Trezor returned an error: %s' % e)
                return 1

            except agent_misc.TrezorNotRunning as e:
                logger.error('Trezor server is not running')
                return 2

        logger.info('Terminating')

    async def sign(self, file):
        """
        Performs TX signature
        :param file:
        :return:
        """
        try:
            await self.trezor_proxy.ping()
        except Exception as e:
            raise agent_misc.TrezorNotRunning(e)

        if not os.path.exists(file):
            raise ValueError('Could not find unsigned transaction file')

        data = None
        with open(file, 'rb') as fh:
            data = fh.read()

        msg = await wallet.load_unsigned_tx(self.priv_view, data)

        # Key image sync
        # key_images = await self.agent.import_outputs(msg.transfers)
        # For now sync only spent key images to the hot wallet.
        key_images = [td.m_key_image for td in msg.transfers]

        txes = []
        pendings = []
        for tx in msg.txes:  # type: xmrtypes.TxConstructionData
            print('Signing transaction with Trezor')
            print('Please check the Trezor and confirm / reject the transaction\n')

            res = await self.agent.sign_transaction_data(tx)
            cdata = self.agent.last_transaction_data()

            # obj = await xmrobj.dump_message(None, res)
            # print(xmrjson.json_dumps(obj, indent=2))

            # Key image sync for spent TXOs
            # Updating only spent.
            for idx in range(len(tx.selected_transfers)):
                idx_mapped = cdata.source_permutation[idx]
                key_images[tx.selected_transfers[idx_mapped]] = res.vin[idx].k_image

            txes.append(await self.agent.serialize_tx(res))
            pending = wallet.construct_pending_tsx(res, tx)
            pendings.append(pending)

            # TODO: store cdata.enc_salt1, cdata.enc_salt2, cdata.enc_keys

        # Key images array has to cover all transfers sent.
        # Watch only wallet does not have key images.
        signed_tx = xmrtypes.SignedTxSet(ptx=pendings, key_images=key_images)
        signed_data = await wallet.dump_signed_tx(self.priv_view, signed_tx)
        with open('signed_monero_tx', 'wb+') as fh:
            fh.write(signed_data)
            logger.info('Signed transaction file: signed_monero_tx')

        print('Key images: %s' % [binascii.hexlify(ff).decode('utf8') for ff in key_images])
        for idx, tx in enumerate(txes):
            fname = 'transaction_%02d' % idx
            with open(fname, 'wb+') as fh:
                fh.write(tx)

            relay_fname = 'transaction_%02d_relay.sh' % idx
            hex_ctx = binascii.hexlify(tx).decode('utf8')
            with open(relay_fname, 'w+') as fh:
                fh.write('#!/bin/bash\n')
                fh.write('curl -X POST http://%s/sendrawtransaction '
                         '-d \'{"tx_as_hex":"%s", "do_not_relay":false}\' '
                         '-H \'Content-Type: application/json\'\n' % (self.args.rpc_addr, hex_ctx))

            print('Transaction %02d stored to %s, relay script: %s' % (idx, fname, relay_fname))

            if self.args.relay:
                print('Relaying...')
                payload = {'tx_as_hex': hex_ctx, 'do_not_relay': False}
                resp = requests.post('http://%s/sendrawtransaction' % (self.args.rpc_addr, ), json=payload)
                print('Relay response: %s' % resp.json())

        print('Please note that by manual relaying hot wallet key images get out of sync')
        return 0

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

        parser.add_argument('--rpc-addr', dest='rpc_addr', default='127.0.0.1:18081',
                            help='RPC address for tsx relay')

        parser.add_argument('--relay', dest='relay', default=False, action='store_const', const=True,
                            help='Relay constructed transactions. Warning! Key images will get out of sync')

        parser.add_argument('--sign', dest='sign', default=None,
                            help='Sign the unsigned file')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging output')

        self.args = parser.parse_args()
        return await self.entry()


async def main():
    agent = HostAgent()
    res = await agent.main()
    sys.exit(res)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    # loop.run_forever()
    loop.close()


