#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging
import traceback
import hashlib


logger = logging.getLogger(__name__)


class Tracelogger(object):
    """
    Prints traceback to the debugging logger if not shown before
    """

    def __init__(self, logger_obj=None):
        self._logger = logger_obj if logger_obj is not None else logger
        self._db = set()

    def log(self, cause=None, do_message=True, custom_msg=None):
        """
        Loads exception data from the current exception frame - should be called inside the except block
        :return:
        """
        traceback_formatted = traceback.format_exc()
        md5 = hashlib.md5(traceback_formatted.encode('utf-8')).hexdigest()

        if md5 in self._db:
            return

        if custom_msg is not None and cause is not None:
            self._logger.debug('%s : %s' % (custom_msg, cause))
        elif custom_msg is not None:
            self._logger.debug(custom_msg)
        elif cause is not None:
            self._logger.debug('%s' % cause)

        self._logger.debug(traceback_formatted)
        self._db.add(md5)

    def set_logger(self, logger_obj):
        """
        Updates internall logging 
        :param logger_obj:
        :return: 
        """
        self._logger = logger_obj if logger_obj is not None else logger

