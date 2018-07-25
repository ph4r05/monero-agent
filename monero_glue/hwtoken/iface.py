#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


class TokenInterface(object):
    def __init__(self, ctx=None):
        self.ctx = ctx

    def gctx(self, ctx):
        return ctx if not None else self.ctx

    async def confirm_transaction(self, tsx_data, creds=None, ctx=None):
        """
        Ask for confirmation from user
        :param tsx_data:
        :param creds:
        :param ctx:
        :return:
        """
        return True

    async def transaction_error(self, *args, **kwargs):
        """
        Transaction error
        :return:
        """

    async def transaction_signed(self, ctx=None):
        """
        Notifies the transaction was completely signed
        :return:
        """

    async def transaction_finished(self, ctx=None):
        """
        Notifies the transaction has been completed (all data were sent)
        :return:
        """

    async def transaction_step(self, step, sub_step=None, sub_step_total=None):
        """
        Transaction progress
        :param step:
        :param sub_step:
        :param sub_step_total:
        :return:
        """

    async def confirm_ki_sync(self, init_msg, ctx=None):
        """
        Ask confirmation on key image sync
        :param init_msg:
        :return:
        """
        return True

    async def ki_error(self, e, ctx=None):
        """
        Key image sync error
        :param e:
        :return:
        """

    async def ki_step(self, i, ctx=None):
        """
        Key image sync step
        :param i:
        :return:
        """

    async def ki_finished(self, ctx=None):
        """
        Ki sync finished
        :return:
        """


def get_iface(ctx=None):
    return TokenInterface(ctx)
