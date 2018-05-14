#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os


EC_BACKEND_PY = 0
EC_BACKEND_TREZOR = 1
EC_BACKEND = EC_BACKEND_TREZOR


def get_ec_backend():
    global EC_BACKEND

    env_back = os.getenv('EC_BACKEND')
    if env_back is not None:
        return int(env_back)

    return EC_BACKEND


def set_ec_backend(x):
    global EC_BACKEND
    env_back = os.getenv('EC_BACKEND')
    if env_back is not None:
        raise ValueError('Could not override Environment variable EC_BACKEND')

    EC_BACKEND = x



