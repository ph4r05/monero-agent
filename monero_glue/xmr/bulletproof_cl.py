#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
# Bulletproof offloading client

import os
import time
import logging
import binascii as ubinascii
from monero_serialize.core.message_types import MessageType
from monero_serialize.xmrtypes import ECKey, KeyV

from monero_glue.hwtoken import misc as tmisc
from monero_glue.xmr import crypto, monero, wallet
from monero_glue.xmr import bulletproof as bp


logger = logging.getLogger(__name__)


class BulletproofFull(MessageType):
    __slots__ = ['V', 'A', 'S', 'T1', 'T2', 'taux', 'mu', 'L', 'R', 'a', 'b', 't']
    MFIELDS = [
        ('V', KeyV),
        ('A', ECKey),
        ('S', ECKey),
        ('T1', ECKey),
        ('T2', ECKey),
        ('taux', ECKey),
        ('mu', ECKey),
        ('L', KeyV),
        ('R', KeyV),
        ('a', ECKey),
        ('b', ECKey),
        ('t', ECKey),
    ]


_tmp_bf_0 = bytearray(32)
_tmp_bf_1 = bytearray(32)

_tmp_pt_1 = crypto.new_point()
_tmp_pt_2 = crypto.new_point()
_tmp_pt_3 = crypto.new_point()
_tmp_pt_4 = crypto.new_point()

_tmp_sc_1 = crypto.new_scalar()
_tmp_sc_2 = crypto.new_scalar()
_tmp_sc_3 = crypto.new_scalar()
_tmp_sc_4 = crypto.new_scalar()


def comp_fold_idx(batching, nprime, i):
    ia0 = 32 * (i * batching)
    ia1 = ia0 + 32 * batching
    ib0 = 32 * (i * batching + nprime)
    ib1 = ib0 + 32 * batching
    return ia0, ia1, ib0, ib1


def comp_folding(rrcons, nprime, v, ix):
    # Compute folding all in memory
    # Gp_{LO, i} = m_0 bl0^{-1} w G_i   +   m_0 bl1^{-1} w^{-1} G_{i+h}
    # Gp_{HI, i} = m_1 bl0^{-1} w G_i   +   m_1 bl1^{-1} w^{-1} G_{i+h}
    P0, P1 = v.slice_view(0, nprime//2), v.slice_view(nprime, nprime + nprime//2)
    P2, P3 = v.slice_view(nprime//2, nprime), v.slice_view(nprime + nprime//2, nprime * 2)
    D0, D1 = v.slice_view(0, nprime//2), v.slice_view(nprime//2, nprime)
    a0, a1 = rrcons[4*ix+0], rrcons[4*ix+1]
    a2, a3 = rrcons[4*ix+2], rrcons[4*ix+3]

    if ix in (0, 1):
        bp.hadamard_fold(P0, a=a0, b=a1, into=D0, vR=P1, full_v=True)
        bp.hadamard_fold(P2, a=a2, b=a3, into=D1, vR=P3, full_v=True)
    else:
        bp.scalar_fold(P0, a=a0, b=a1, into=D0, vR=P1, full_v=True)
        bp.scalar_fold(P2, a=a2, b=a3, into=D1, vR=P3, full_v=True)
    v.resize(nprime)
    return v


def comp_offdots(Gprime, Hprime, aprime, bprime, nprime):
    # Computing dot products in-memory, blinded
    npr2 = nprime * 2
    cL = bp.inner_product(
        aprime.slice_view(0, nprime), bprime.slice_view(nprime, npr2), None
    )

    cR = bp.inner_product(
        aprime.slice_view(nprime, npr2), bprime.slice_view(0, nprime), None
    )

    LcA = bp.vector_sum_aA(None, aprime.slice_view(0, nprime), Gprime.slice_view(nprime, npr2))
    LcB = bp.vector_sum_aA(None, bprime.slice_view(nprime, npr2), Hprime.slice_view(0, nprime))

    RcA = bp.vector_sum_aA(None, aprime.slice_view(nprime, npr2), Gprime.slice_view(0, nprime))
    RcB = bp.vector_sum_aA(None, bprime.slice_view(0, nprime), Hprime.slice_view(nprime, npr2))
    return cL, cR, LcA, LcB, RcA, RcB


def dechunk_res(buffers, exp_res=1):
    if not buffers or not isinstance(buffers, (list, tuple)):
        return buffers

    ln = len(buffers)
    cres = [bytearray() for _ in range(exp_res)]
    for c in range(exp_res):
        cbuff = buffers[c] if exp_res > 1 else buffers
        if not isinstance(cbuff, (list, tuple)):
            cres[c] += cbuff
            continue

        for i in range(len(cbuff)):
            cres[c] += cbuff[i]

    return cres if exp_res > 1 else cres[0]


def vect_clone(dst, src):
    dst = bp.ensure_dst_keyvect(dst, len(src))
    for i in range(len(src)):
        dst.read(i, src.to(i))
    return dst


def count_bytes(buffers):
    if buffers is None:
        return 0
    if isinstance(buffers, (list, tuple)):
        return sum([count_bytes(x) for x in buffers])
    elif isinstance(buffers, (bytearray, bytes, str)):
        return len(buffers)
    else:
        logger.debug("Unknown type for count_bytes(): %s " % (type(buffers),))
        return 0


class BulletproofClient:
    def __init__(self, m=1, messenger=None):
        # Main sending coroutine
        # Arguments: p1, p2, params, buffers
        self.messenger = messenger

        self.off_method = 3
        self.nprime_thresh = 64
        self.batching = 32
        self.off2_thresh = 32
        self.M = m
        self.MN = 64 * self.M

        self.is_debug = True
        self.do_timing = True
        self.time_start = None
        self.timing_bins = {}
        self.n_msgs = 0
        self.n_sent = 0
        self.n_recv = 0
        self.prove_time = 0

    async def comm(self, p1=0, p2=0, params=None, buffers=None):
        return await self.messenger(p1, p2, params, buffers)

    async def bp_tx_buffers(self, buffers=None):
        buffers = buffers if buffers else []
        self.n_msgs += 1
        self.n_sent += count_bytes(buffers)
        r = await self.comm(p1=1, p2=0, buffers=buffers)
        self.n_recv += count_bytes(r)
        return r

    async def bp_final(self):
        self.n_msgs += 1
        r = await self.comm(p1=1, p2=0)
        self.n_recv += count_bytes(r)
        return r

    async def bp_start(self, ln, offm=2, nprime_thresh=32, off2_thresh=32, batching=32):
        self.n_msgs += 1
        r = await self.comm(p1=0, p2=ln, params=[offm, nprime_thresh, off2_thresh, batching])
        self.n_recv += count_bytes(r)
        return r

    async def compute_bp(self):
        ln = self.M
        self.MN = 64 * ln

        bpi = bp.BulletProofBuilder()
        l = bytearray()
        r = bytearray()
        aprime = l
        bprime = r
        logger.debug('Batching: %s, MN: %s, chunks: %s, M: %s' % (self.batching, self.MN, self.MN // self.batching, ln))

        ttstart = time.time()
        l0, r0 = dechunk_res(await self.bp_start(ln, self.off_method, self.nprime_thresh, self.off2_thresh, self.batching), 2)
        l += l0
        r += r0

        for i in range(1, self.MN // self.batching):
            logger.debug('.. l, r: %s' % i)
            l0, r0 = dechunk_res(await self.bp_tx_buffers(None), 2)
            l += l0
            r += r0

        logger.debug('l, r finished')
        rrcons = await self.bp_tx_buffers(None)
        logger.debug('Phase 1 finishing: %s' % rrcons)
        logger.debug('Phase 1 finished')

        y = rrcons[0] if rrcons and len(rrcons) > 0 else None

        # First while-loop iteration, dot-product computation, lC, lR, Lc, Lr, w, winv
        if self.off_method == 0:
            # round 0 - aLow, bHigh
            logger.debug('r0, cLcR aLow')
            for i in range(self.MN // self.batching // 2):
                ia0, ia1, ib0, ib1 = comp_fold_idx(self.batching, self.MN // 2, i)
                logger.debug(' .. i: %s, %s:%s, %s:%s' % (i, ia0, ia1, ib0, ib1))
                rrcons = await self.bp_tx_buffers((l[ia0:ia1], r[ib0:ib1]))
                logger.debug(rrcons)

            # round 0 - aHigh, bLow
            logger.debug('r0, cLcR aHigh')
            for i in range(self.MN // self.batching // 2):
                ib0, ib1, ia0, ia1 = comp_fold_idx(self.batching, self.MN // 2, i)
                logger.debug(' .. i: %s, %s:%s, %s:%s' % (i, ia0, ia1, ib0, ib1))
                rrcons = await self.bp_tx_buffers((l[ia0:ia1], r[ib0:ib1]))
                logger.debug(rrcons)

        else:
            # round 0 - aLow, bHigh; aHigh, bLow in memory
            logger.debug('r0, cLcR off, nprime: %s' % str(self.MN // 2))
            yinvpow = vect_clone(None, bp.KeyVPowers(self.MN, bp.invert(None, y)))
            Gprec = vect_clone(None, bpi._gprec_aux(self.MN))
            Hprec = vect_clone(None, bpi._hprec_aux(self.MN))
            Hprime = vect_clone(None, bp.KeyVEval(self.MN, lambda i, d: bp.scalarmult_key(d, Hprec[i], yinvpow[i])))

            cL, cR, LcA, LcB, RcA, RcB = comp_offdots(Gprec, Hprime, bp.KeyV(self.MN, l), bp.KeyV(self.MN, r), self.MN // 2)
            rrcons = await self.bp_tx_buffers((cL, cR, LcA, LcB, RcA, RcB))
            logger.debug(rrcons)

        # round 0 folding, G, H, a, b
        Gprime = bytearray()
        Hprime = bytearray()
        app = bytearray()
        bpp = bytearray()
        cbatch = max(1, self.MN // 2 // self.batching // 2)

        logger.debug('r0, fold G')
        for i in range(cbatch):
            cres = dechunk_res(await self.bp_tx_buffers(None))
            if cres: Gprime += cres

        logger.debug('r0, fold H')
        for i in range(cbatch):
            cres = dechunk_res(await self.bp_tx_buffers(None))
            if cres: Hprime += cres

        Gprime = bp.KeyV(self.MN // 2, Gprime)
        Hprime = bp.KeyV(self.MN // 2, Hprime)

        if self.off_method == 3:
            logger.debug('r0 in-mem meth3 fold Gprime')
            Gprec = vect_clone(None, bpi._gprec_aux(self.MN))
            comp_folding(rrcons, self.MN // 2, Gprec, 0)

            logger.debug('r0 in-mem meth3 fold Hprime')
            Hprec_ = vect_clone(None, bpi._hprec_aux(self.MN))
            ypowinv = vect_clone(None, bp.KeyVPowers(self.MN, bp.invert(_tmp_bf_0, y)))
            Hprec = vect_clone(None, bp.KeyVEval(self.MN, lambda i, d: bp.scalarmult_key(d, Hprec_.to(i), yinvpow[i])))
            comp_folding(rrcons, self.MN // 2, Hprec, 1)

            logger.debug('r0 in-mem meth3 correct G, H')
            for i in range(self.MN // 2):
                crypto.decodepoint_into(_tmp_pt_1, Gprec.to(i))
                crypto.decodepoint_into(_tmp_pt_2, Gprime.to(i))
                crypto.point_sub_into(_tmp_pt_1, _tmp_pt_1, _tmp_pt_2)
                crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_1)
                Gprime.read(i, _tmp_bf_0)

                crypto.decodepoint_into(_tmp_pt_1, Hprec.to(i))
                crypto.decodepoint_into(_tmp_pt_2, Hprime.to(i))
                crypto.point_sub_into(_tmp_pt_1, _tmp_pt_1, _tmp_pt_2)
                crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_1)
                Hprime.read(i, _tmp_bf_0)

        if self.off_method >= 2:
            logger.debug('in-mem fold for a, b')
            aprime = bp.KeyV(self.MN, l)
            bprime = bp.KeyV(self.MN, r)
            comp_folding(rrcons, self.MN // 2, aprime, 2)
            comp_folding(rrcons, self.MN // 2, bprime, 3)

        else:
            logger.debug('r0, fold a')
            for i in range(self.MN // self.batching // 2):
                ia0, ia1, ib0, ib1 = comp_fold_idx(self.batching, self.MN // 2, i)
                cres = dechunk_res(await self.bp_tx_buffers((aprime[ia0:ia1], aprime[ib0:ib1])))
                if cres: app += cres

            logger.debug('r0, fold b')
            for i in range(self.MN // self.batching // 2):
                ia0, ia1, ib0, ib1 = comp_fold_idx(self.batching, self.MN // 2, i)
                cres = dechunk_res(await self.bp_tx_buffers((bprime[ia0:ia1], bprime[ib0:ib1])))
                if cres: bpp += cres

            aprime = bp.KeyV(self.MN // 2, app)
            bprime = bp.KeyV(self.MN // 2, bpp)

        logger.debug('0PC r: %s, ap %s %s' % (0, len(aprime), ubinascii.hexlify(aprime.d[-64:])))
        logger.debug('0PC r: %s, bp %s %s' % (0, len(bprime), ubinascii.hexlify(bprime.d[-64:])))
        logger.debug('0PC r: %s, Gp %s %s' % (0, len(Gprime), ubinascii.hexlify(Gprime.d[-64:])))
        logger.debug('0PC r: %s, Hp %s %s' % (0, len(Hprime), ubinascii.hexlify(Hprime.d[-64:])))

        # Loops:
        # - clcr part, compute blinded cL, cR, LcA, LcB, RcA, RcB
        nprime = self.MN // 4
        round = 0
        while round == 0 or nprime >= self.nprime_thresh or (self.off_method >= 2 and nprime >= self.off2_thresh):
            npr2 = nprime * 2
            round += 1

            logger.debug('Client, BPI nprime: %s, CLI nprime: %s, |Gprime|: %s' % (nprime, nprime, len(Gprime)))
            if self.off_method == 0:
                # round 0 - aLow, bHigh
                logger.debug('r%s, cLcR aLow' % round)
                for i in range(nprime // self.batching):
                    ia0, ia1, ib0, ib1 = comp_fold_idx(self.batching, nprime, i)
                    logger.debug(' .. i: %s, %s:%s, %s:%s' % (i, ia0, ia1, ib0, ib1))
                    rrcons = await self.bp_tx_buffers(
                        (aprime.d[ia0:ia1], bprime.d[ib0:ib1], Gprime.d[ib0:ib1], Hprime.d[ia0:ia1]))
                    logger.debug(rrcons)

                # round 0 - aHigh, bLow
                logger.debug('r%s, cLcR aHigh' % round)
                for i in range(nprime // self.batching):
                    ib0, ib1, ia0, ia1 = comp_fold_idx(self.batching, nprime, i)
                    logger.debug(' .. i: %s, %s:%s, %s:%s' % (i, ia0, ia1, ib0, ib1))
                    rrcons = await self.bp_tx_buffers(
                        (aprime.d[ia0:ia1], bprime.d[ib0:ib1], Gprime.d[ib0:ib1], Hprime.d[ia0:ia1]))
                    logger.debug(rrcons)

            else:
                # Computing dot products in-memory, blinded
                cL, cR, LcA, LcB, RcA, RcB = comp_offdots(Gprime, Hprime, aprime, bprime, nprime)
                logger.debug('clcr step, r %s' % round)
                rrcons = await self.bp_tx_buffers((cL, cR, LcA, LcB, RcA, RcB))
                logger.debug(rrcons)

            for ix, v in enumerate((Gprime, Hprime, aprime, bprime)):
                logger.debug('Folding IX: %s, r %s' % (ix, round))

                # Offloaded folding up to batching limit / limit defined by Trezor
                # Can be e.g. 8 elements. Remaining 8 computed in memory in the Trezor
                if self.off_method >= 2 and rrcons:
                    logger.debug('.. PC: in-memory fold, len: %s; %s' % (len(v), nprime))
                    comp_folding(rrcons, nprime, v, ix)

                    if ix == 3:
                        nprime >>= 1
                    continue

                # Ordinary folding for methods [0, 1]
                bf = v.d
                nf = bytearray()
                cbatching = min(self.batching, nprime)
                for i in range(max(1, nprime // cbatching)):
                    ia0, ia1, ib0, ib1 = comp_fold_idx(self.batching, nprime, i)
                    logger.debug(' .. i: %s, %s:%s, %s:%s' % (i, ia0, ia1, ib0, ib1))

                    lo = bf[ia0:ia1]
                    hi = bf[ib0:ib1]

                    cres = dechunk_res(await self.bp_tx_buffers((lo, hi)))
                    if cres:
                        nf += cres

                nf = bp.KeyV(nprime // 2, nf)
                if ix == 0:
                    Gprime = nf
                elif ix == 1:
                    Hprime = nf
                elif ix == 2:
                    aprime = nf
                elif ix == 3:
                    bprime = nf
                    nprime >>= 1

            logger.debug('wPC r: %s, ap  %s %s' % (round, len(aprime), ubinascii.hexlify(aprime.d[-64:])))
            logger.debug('wPC r: %s, bp  %s %s' % (round, len(bprime), ubinascii.hexlify(bprime.d[-64:])))
            logger.debug('wPC r: %s, Gp  %s %s' % (round, len(Gprime), ubinascii.hexlify(Gprime.d[-64:])))
            logger.debug('wPC r: %s, Hp  %s %s' % (round, len(Hprime), ubinascii.hexlify(Hprime.d[-64:])))

        proof = await self.bp_final()
        proof = await tmisc.parse_msg(proof[0], BulletproofFull())
        self.prove_time = time.time() - ttstart
        return proof


class BulletproofMPCRunner:
    def __init__(self):
        self.state = None
        self.prev_mem = 0
        self.cur_mes = 0

    def bpp(self, instance=None):
        if instance:
            self.state = instance
        return self.state

    def check_mem(self, x):
        # gc.collect()
        free = 0  # gc.mem_free()
        diff = self.prev_mem - free
        logger.debug(
            "======= {} {} Diff: {} Free: {} Allocated: {}".format(
                self.cur_mes, x, diff, free, '?', # gc.mem_alloc()
            ),
        )
        # micropython.mem_info()
        # gc.collect()
        self.cur_mes += 1
        self.prev_mem = free

    def log_trace(self, x=None):
        logger.debug(
            "Log trace %s, ... F: %s A: %s, S: %s",
            x,
            '?',  # gc.mem_free(),
            '?',  # gc.mem_alloc(),
            '?',  # micropython.stack_use(),
        )

    async def step(self, p1=0, p2=2, params=None, buffers=None):
        if p1 == 0:
            self.bpp(None)  # clear old state

        self.check_mem("+++BP START: %s; %s" % (p1, p2))
        # gc.collect()
        self.log_trace("BP START")

        # Crypto function call number reporting not implemented here
        # It is in git: ph4r05/trezor-firmware/pr/bpoff-counting-exp

        bpi, res = None, None
        if p1 == 0:
            # crypto.report_reset()
            bp.set_prng(crypto.prng(bp.ZERO))
            bpi = bp.BulletProofBuilder()
            # bpi.gc_fnc = gc.collect
            bpi.gc_trace = self.log_trace
            sv = [crypto.sc_init(137 * i) for i in range(p2)]
            gamma = [crypto.sc_init(991 * i) for i in range(p2)]

            bpi.off_method = 2 if not params and len(params) <= 1 else params[0]
            if params and len(params) >= 4:
                bpi.nprime_thresh = params[1]
                bpi.off2_thresh = params[2]
                bpi.batching = params[3]

            res = bpi.prove_batch_off(sv, gamma, buffers)
            # crypto.report()
            state = bpi.dump_state()
            # del (bp, bpi)
            # gc.collect()
            self.log_trace("BP STATE")
            self.bpp((state, None))
            # self.bpp((state, crypto.report_get()))
            # del (crypto)
            # gc.collect()
            self.log_trace("BP STATE2")

        else:
            # crypto.report_reset()
            state, fncs = self.bpp()
            bpi = bp.BulletProofBuilder()
            bpi.load_state(state)
            del (state)
            self.bpp(None)
            # gc.collect()
            self.log_trace("From state")

            # bp.PRNG = crypto.prng(bp._ZERO)
            # bpi.gc_fnc = gc.collect
            bpi.gc_trace = self.log_trace

            # crypto.report_reset()
            # crypto.report_set(fncs)
            res = bpi.prove_batch_off_step(buffers)
            # crypto.report()
            state = bpi.dump_state()
            del bpi
            # del (bp, bpi)
            # gc.collect()
            self.log_trace("BP STATE")
            self.bpp((state, fncs))
            # del (crypto)
            # gc.collect()
            self.log_trace("BP STATE2")

        # gc.collect()
        self.log_trace("BP STEP")
        self.check_mem("+++BP STEP")
        if isinstance(res, tuple) and res[0] == 1:
            from monero_glue.hwtoken import misc as tmisc
            B = res[1]
            B2 = BulletproofFull()
            B2.V = B.V
            B2.S = B.S
            B2.A = B.A
            B2.T1 = B.T1
            B2.T2 = B.T2
            B2.taux = B.taux
            B2.mu = B.mu
            B2.L = B.L
            B2.R = B.R
            B2.a = B.a
            B2.b = B.b
            B2.t = B.t
            res = await tmisc.dump_msg(B2)

        msg = None
        if res:
            msg = res if isinstance(res, (list, tuple)) else [res]
        return msg
