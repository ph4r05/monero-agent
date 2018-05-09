#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


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

    async def confirm_ki_sync(self, init_msg):
        """
        Ask confirmation on key image sync
        :param init_msg:
        :return:
        """
        return True

    async def ki_error(self, e):
        """
        Key image sync error
        :param e:
        :return:
        """

    async def ki_step(self, i):
        """
        Key image sync step
        :param i:
        :return:
        """

    async def ki_finished(self):
        """
        Ki sync finished
        :return:
        """

