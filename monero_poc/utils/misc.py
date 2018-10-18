#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import asyncio
import binascii
import collections
import json
import logging
import os
import random
import re
import signal
import string
import subprocess
import sys
import threading
import time
import traceback
from shlex import quote

from monero_glue.hwtoken.misc import TrezorError
from monero_glue.xmr import crypto
from monero_glue.xmr.monero import DISPLAY_DECIMAL_POINT

import shellescape
from sarge import Capture, Feeder, run

logger = logging.getLogger(__name__)


PRIORITIES = ["default", "unimportant", "normal", "elevated", "priority"]


class TrezorCallError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorNotConfiguredError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorAddressMismatchError(TrezorError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class CliPrompt(object):
    """
    Synchronous CLI confirmation waiter.
    """

    def __init__(self, pre_wait_hook=None, *args, **kwargs):
        self.in_confirmation = False
        self.conf_evt = None
        self.confirmed_result = False
        self.pre_wait_hook = pre_wait_hook

    def confirmation(self, confirmed):
        self.confirmed_result = confirmed
        self.in_confirmation = False
        self.conf_evt.set()

    def _init_wait(self):
        self.in_confirmation = True
        self.confirmed_result = False
        self.conf_evt = threading.Event()

    def wait_confirmation(self):
        """
        Synchronous waiting
        :return:
        """
        self._init_wait()
        if self.pre_wait_hook:
            self.pre_wait_hook()

        try:
            self.conf_evt.wait()
            return self.confirmed_result

        finally:
            self.in_confirmation = False

    async def async_wait_confirmation(self):
        """
        Asynchronous waiting
        Asyncio waiting not implemented.

        :return:
        """
        self._init_wait()
        try:
            # TODO: asyncio wait
            # TODO: eventlet could require another locking mechanism
            self.conf_evt.wait()
            return self.confirmed_result

        finally:
            self.in_confirmation = False

    def __enter__(self):
        self._init_wait()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.in_confirmation = False


def py_raw_input(question=None):
    """
    Python compatibility wrapper for standard raw_input()
    :param question:
    :return:
    """
    return input(question)


def gen_simple_passwd(n):
    """
    Generates simple alphanum passwd.
    TODO: stronger passwd
    :param n:
    :return:
    """
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(n)
    )


def amount_to_uint64(amount):
    return int((10 ** DISPLAY_DECIMAL_POINT) * amount)


class TransferArgs(object):
    def __init__(self):
        self.indices = []
        self.priority = None
        self.mixin = None
        self.address_amounts = []
        self.address = None
        self.amount = None
        self.payment_id = None
        self.amount_threshold = None
        self.key_image = None


def cut_index(parts):
    if not parts[0].startswith("index="):
        return [], parts

    return [int(x.strip()) for x in parts[0][6:].split(",")], parts[1:]


def cut_priority(parts):
    idx = None
    for i, x in enumerate(PRIORITIES):
        if parts[0] == x:
            idx = i
            break

    if idx is not None:
        return idx, parts[1:]
    return None, parts


def cut_mixin(parts):
    try:
        return int(parts[0]), parts[1:]
    except Exception as e:
        return None, parts


def cut_addr(parts):
    return parts[0], parts[1:]


def cut_amount(parts):
    try:
        return float(parts[0]), parts[1:]
    except Exception as e:
        raise ValueError("Format error, Amount not valid") from e


def cut_addr_amount(parts):
    try:
        return parts[0], float(parts[1]), parts[2:]
    except Exception as e:
        return None, None, parts


def cut_key_image(parts):
    ki = parts[0]
    if len(ki) != 64:
        raise ValueError("Format error, Key Image have to be exactly 32B long")
    try:
        return binascii.unhexlify(ki), parts[1:]
    except Exception as e:
        raise ValueError("Format error, Key Image is not properly hex-coded") from e


def cut_payment_id(parts):
    if len(parts) == 0:
        return None, parts
    payment_id = parts[0]
    if len(payment_id) != 16 and len(payment_id) != 64:
        raise ValueError("Payment ID allowed only 8 and 32 B")
    return payment_id, parts[1:]


def parse_transfer_cmd(parts):
    """
    Parses transfer command format
    transfer [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> <amount> [<payment_id>]
    :param parts:
    :return:
    """
    if len(parts) < 2:
        raise ValueError("Format error, too few arguments")

    parts = list(parts)  # copy
    res = TransferArgs()
    res.indices, parts = cut_index(parts)
    res.priority, parts = cut_priority(parts)
    res.mixin, parts = cut_mixin(parts)
    res.address_amounts = []

    while True:
        addr, amount, parts = cut_addr_amount(parts)
        if addr is None:
            break

        res.address_amounts.append((addr, amount))

    if len(res.address_amounts) == 0:
        raise ValueError("Format error")

    res.payment_id, parts = cut_payment_id(parts)
    return res


def parse_sweep_all(line):
    """
    sweep_all [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> [<payment_id>]
    :param line:
    :return:
    """
    parts = [x for x in line.split(" ") if len(x.strip()) > 0]
    res = TransferArgs()
    res.indices, parts = cut_index(parts)
    res.priority, parts = cut_priority(parts)
    res.mixin, parts = cut_mixin(parts)
    res.address, parts = cut_addr(parts)
    res.payment_id, parts = cut_payment_id(parts)
    return res


def parse_sweep_below(line):
    """
    sweep_below <amount_threshold> [index=<N1>[,<N2>,...]] [<priority>] [<ring_size>] <address> [<payment_id>]
    :param line:
    :return:
    """
    parts = [x for x in line.split(" ") if len(x.strip()) > 0]
    if len(parts) < 2:
        raise ValueError("Invalid format")

    res = TransferArgs()
    res.amount_threshold, parts = cut_amount(parts)
    res.indices, parts = cut_index(parts)
    res.priority, parts = cut_priority(parts)
    res.mixin, parts = cut_mixin(parts)
    res.address, parts = cut_addr(parts)
    res.payment_id, parts = cut_payment_id(parts)
    return res


def parse_sweep_single(line):
    """
    sweep_single [<priority>] [<ring_size>] <key_image> <address> [<payment_id>]
    :param line:
    :return:
    """
    parts = [x for x in line.split(" ") if len(x.strip()) > 0]
    if len(parts) < 2:
        raise ValueError("Invalid format")

    res = TransferArgs()
    res.priority, parts = cut_priority(parts)
    res.mixin, parts = cut_mixin(parts)
    res.key_image, parts = cut_key_image(parts)
    res.address, parts = cut_addr(parts)
    res.payment_id, parts = cut_payment_id(parts)
    return res


class SargeLogFilter(logging.Filter):
    """Filters out debugging logs generated by sarge - output capture. It is way too verbose for debug"""

    def __init__(self, name="", *args, **kwargs):
        self.namex = name
        logging.Filter.__init__(self, *args, **kwargs)

    def filter(self, record):
        if record.levelno != logging.DEBUG:
            return 1

        try:
            # Parse messages are too verbose, skip.
            if record.name == "sarge.parse":
                return 0

            # Disable output processing message - length of one character.
            msg = record.getMessage()
            if "queued chunk of length 1" in msg:
                return 0

            return 1

        except Exception as e:
            logger.error("Exception in log filtering: %s" % e)

        return 1


def install_sarge_filter():
    """
    Installs Sarge log filter to avoid long 1char debug dumps
    :return:
    """
    for handler in logging.getLogger().handlers:
        handler.addFilter(SargeLogFilter("hnd"))
    logging.getLogger().addFilter(SargeLogFilter("root"))


def sarge_sigint(proc):
    """
    Sends sigint to sarge process
    :return:
    """
    proc.process_ready.wait()
    p = proc.process
    if not p:  # pragma: no cover
        raise ValueError("There is no subprocess")
    p.send_signal(signal.SIGINT)


def escape_shell(inp):
    """
    Shell-escapes input param
    :param inp:
    :return:
    """
    try:
        inp = inp.decode("utf8")
    except:
        pass

    try:
        return shellescape.quote(inp)
    except:
        pass

    quote(inp)


def wallet_enc_key(salt, password):
    """
    Chacha20 password derivation for view key storage
    :param salt:
    :param password:
    :return:
    """
    return crypto.pbkdf2(password, salt, count=2048)
