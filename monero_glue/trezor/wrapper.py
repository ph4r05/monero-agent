#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


MONERO_CURVE = "ed25519-keccak"


async def monero_get_creds(ctx, address_n=None, network_type=None):
    """
    Credentials derivation method.
    In the emulated setup (no trezor environment) this fallbacks to retrieving credentials
    from the context (trezor lite).

    :param ctx:
    :param address_n:
    :param network_type:
    :return:
    """
    return await ctx.monero_get_creds(address_n=address_n, network_type=network_type)


def get_interface(ctx):
    return ctx.get_iface()
