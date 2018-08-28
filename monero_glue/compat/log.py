#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import logging

logger = logging.getLogger(__name__)


def debug(name, msg, *args):
    logger = logging.getLogger(name)
    logger.debug(msg, *args)


def info(name, msg, *args):
    logger = logging.getLogger(name)
    logger.info(msg, *args)


def warning(name, msg, *args):
    logger = logging.getLogger(name)
    logger.warning(msg, *args)


def error(name, msg, *args):
    logger = logging.getLogger(name)
    logger.error(msg, *args)


def exception(name, exc):
    logger = logging.getLogger(name)
    logger.error(exc)


def critical(name, msg, *args):
    logger = logging.getLogger(name)
    logger.error(msg, *args)
