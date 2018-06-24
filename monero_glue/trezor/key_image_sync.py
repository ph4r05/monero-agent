#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from monero_glue import trezor_iface, trezor_misc
from monero_glue.xmr import monero, crypto, common, key_image
from monero_glue.xmr.enc import chacha_poly
from monero_glue.trezor import wrapper as twrap

from monero_glue.messages import MoneroKeyImageSync, MoneroExportedKeyImage, \
    MoneroKeyImageExportInit, MoneroKeyImageExportInitResp, \
    MoneroKeyImageSyncStep, MoneroKeyImageSyncStepResp, \
    MoneroKeyImageSyncFinal, MoneroKeyImageSyncFinalResp, \
    MoneroRespError


class KeyImageSync(object):
    def __init__(self, ctx=None, iface=None, creds=None):
        self.ctx = ctx
        self.iface = iface  # type: trezor_iface.TrezorInterface
        self.creds = creds  # type: monero.AccountCreds

        self.num = 0
        self.c_idx = -1
        self.hash = None
        self.blocked = None
        self.enc_key = None
        self.subaddresses = {}
        self.hasher = common.HashWrapper(crypto.get_keccak())

    async def derive_creds(self, msg: MoneroKeyImageExportInit):
        self.creds = await twrap.monero_get_creds(self.ctx, msg.address_n or (), msg.network_type)

    async def init(self, ctx, msg: MoneroKeyImageExportInit):
        self.ctx = ctx
        await self.derive_creds(msg)

        confirmation = await self.iface.confirm_ki_sync(msg, ctx=ctx)
        if not confirmation:
            return MoneroRespError(reason='rejected')

        self.num = msg.num
        self.hash = msg.hash
        self.enc_key = crypto.random_bytes(32)

        # Sub address precomputation
        if msg.subs and len(msg.subs) > 0:
            for sub in msg.subs:  # type: key_image.MoneroSubAddrIndicesList
                monero.compute_subaddresses(self.creds, sub.account, sub.minor_indices, self.subaddresses)
        return MoneroKeyImageExportInitResp()

    async def sync(self, ctx, tds: MoneroKeyImageSyncStep):
        self.ctx = ctx
        if self.blocked:
            raise ValueError('Blocked')
        if len(tds.tdis) == 0:
            raise ValueError('Empty')
        resp = []
        for td in tds.tdis:
            self.c_idx += 1
            if self.c_idx >= self.num:
                raise ValueError('Too many outputs')

            hash = key_image.compute_hash(td)
            self.hasher.update(hash)

            ki, sig = await key_image.export_key_image(self.creds, self.subaddresses, td)

            buff = crypto.encodepoint(ki)
            buff += crypto.encodeint(sig[0][0])
            buff += crypto.encodeint(sig[0][1])

            nonce, ciph, tag = chacha_poly.encrypt(self.enc_key, buff)
            eki = MoneroExportedKeyImage(iv=nonce, tag=tag, blob=ciph)
            resp.append(eki)
        return MoneroKeyImageSyncStepResp(kis=resp)

    async def final(self, ctx, msg=None):
        self.ctx = ctx
        if self.blocked:
            raise ValueError('Blocked')

        if self.c_idx + 1 != self.num:
            await self.iface.ki_error('Invalid number of outputs', ctx=self.ctx)
            raise ValueError('Invalid number of outputs')

        final_hash = self.hasher.digest()
        if final_hash != self.hash:
            await self.iface.ki_error('Invalid hash', ctx=self.ctx)
            raise ValueError('Invalid hash')

        return MoneroKeyImageSyncFinalResp(enc_key=self.enc_key)



