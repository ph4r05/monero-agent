#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import sys
import os
import time
import json
import asyncio
import binascii
import logging
import traceback
import threading
import collections

logger = logging.getLogger(__name__)


class CliPrompt(object):
    """
    Synchronous CLI confirmation waiter.
    """

    def __init__(self):
        self.in_confirmation = False
        self.conf_evt = None
        self.confirmed_result = False

    def confirmation(self, confirmed):
        self.confirmed_result = confirmed
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


