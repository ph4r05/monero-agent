#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii

from monero_serialize import xmrtypes, xmrserialize
from .monero import TsxData, classify_subaddresses
from . import monero, crypto, ring_ct, mlsag2, aesgcm
from . import common as common
from . import trezor


class TrezorInterface(object):
    def __init__(self):
        pass

    async def confirm_transaction(self, tsx_data):
        """
        Ask for confirmation from user
        :param tsx_data:
        :return:
        """
        return True

    async def transaction_error(self, *args, **kwargs):
        """
        Transaction error
        :return:
        """

    async def transaction_signed(self):
        """
        Notifies the transaction was completely signed
        :return:
        """

    async def transaction_finished(self):
        """
        Notifies the transaction has been completed (all data were sent)
        :return:
        """

    async def transaction_step(self, step, sub_step=None):
        """
        Transaction progress
        :param step:
        :param sub_step:
        :return:
        """

