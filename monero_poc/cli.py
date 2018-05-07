#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os
import getpass
import asyncio
import sys
import time
import json
import logging
from blessed import Terminal
from cmd2 import Cmd

from . import trace_logger
from . import misc

logger = logging.getLogger(__name__)


class BaseCli(Cmd):
    """
    Base CLI class
    """
    prompt = '$> '
    PROCEED_YES = 'yes'
    PROCEED_NO = 'no'
    PROCEED_QUIT = 'quit'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace_logger = trace_logger.Tracelogger(logger)
        self.t = Terminal()
        self.noninteractive = False

    def get_term_width(self):
        """
        Returns terminal width
        :return: terminal width in characters or 80 if exception encountered
        """
        try:
            width = self.t.width
            if width is None or width <= 0:
                return 80

            return width
        except:
            pass
        return 80

    def ask_password(self, question=None, double_verify=False):
        """
        Ask user for password
        :param question:
        :param double_verify:
        :return:
        """
        question = question if question is not None else 'Please enter the password'

        while True:
            passwd = getpass.getpass(question + '\n')
            if not double_verify:
                return passwd

            passwd2 = getpass.getpass('Please enter the password again for verification: \n')
            if passwd != passwd2:
                print('Error: password did\'t match. Please, try again\n')
            else:
                return passwd

    def ask_proceed_quit(self, question=None, support_non_interactive=False,
                         non_interactive_return=PROCEED_YES, quit_enabled=True):
        """
        Ask if user wants to proceed
        :param question:
        :param support_non_interactive:
        :param non_interactive_return:
        :param quit_enabled:
        :return:
        """
        opts = 'Y/n/q' if quit_enabled else 'Y/n'
        question = question if question is not None else ('Do you really want to proceed? (%s): ' % opts)

        if self.noninteractive and not support_non_interactive:
            raise ValueError('Non-interactive mode not supported for this prompt')

        # Classic interactive prompt
        confirmation = None
        while confirmation != 'y' and confirmation != 'n' and confirmation != 'q':
            confirmation = misc.py_raw_input(question).strip().lower()

        if confirmation == 'y':
            return self.PROCEED_YES
        elif confirmation == 'n':
            return self.PROCEED_NO
        else:
            return self.PROCEED_QUIT

    #
    # Handlers
    #

    do_q = quit
    do_Q = quit




