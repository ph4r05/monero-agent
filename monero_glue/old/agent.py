#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Educational use only.
# One pass signature, not maintained
# DEPRECATED

from monero_serialize import xmrtypes
from monero_glue.xmr import monero
from monero_glue.old import trezor


class TData(object):
    """
    Agent transaction-scoped data
    """
    def __init__(self):
        self.tsx_data = None  # type: monero.TsxData
        self.tx = xmrtypes.Transaction(vin=[], vout=[], extra=[])
        self.tx_in_hmacs = []
        self.source_permutation = []


class Agent(object):
    """
    Glue agent, running on host
    """
    def __init__(self, trezor):
        self.trezor = trezor
        self.ct = None  # type: TData

    async def transfer_unsigned(self, unsig):
        txes = []
        for tx in unsig.txes:
            self.ct = TData()

            payment_id = []
            extras = await monero.parse_extra_fields(tx.extra)
            extra_nonce = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraNonce)
            if extra_nonce and monero.has_encrypted_payment_id(extra_nonce.nonce):
                payment_id = monero.get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce)

            # Init transaction
            tsx_data = trezor.TsxData()
            tsx_data.version = 1
            tsx_data.payment_id = payment_id
            tsx_data.unlock_time = tx.unlock_time
            tsx_data.outputs = tx.splitted_dsts
            tsx_data.change_dts = tx.change_dts
            tsx_data.num_inputs = len(tx.sources)
            tsx_data.mixin = len(tx.sources[0].outputs)
            tsx_data.fee = sum([x.amount for x in tx.sources]) - sum([x.amount for x in tx.splitted_dsts])

            self.ct.tsx_data = tsx_data
            await self.trezor.init_transaction(tsx_data)

            # Subaddresses
            await self.trezor.precompute_subaddr(tx.subaddr_account, tx.subaddr_indices)

            # Set transaction inputs
            for idx, src in enumerate(tx.sources):
                vini, vini_hmac = await self.trezor.set_tsx_input(src)
                self.ct.tx.vin.append(vini)
                self.ct.tx_in_hmacs.append(vini_hmac)

            await self.trezor.tsx_inputs_done()

            for dst in tx.splitted_dsts:
                await self.trezor.set_tsx_output1(dst)

            # One pass protocol, python Monero implementation / port
            buf = await self.trezor.tsx_obj.signature(tx)
            txes.append(buf)
        return txes


