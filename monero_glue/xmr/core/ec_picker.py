#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import os


EC_BACKEND_PY = 0
EC_BACKEND_TREZOR = 1
EC_BACKEND = EC_BACKEND_TREZOR
EC_BACKEND_FORCE = 0


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


def get_ec_backend_force():
    global EC_BACKEND_FORCE
    en = os.getenv('EC_BACKEND_FORCE', None)
    if en is not None:
        return bool(en)

    return EC_BACKEND_FORCE


def set_ec_backend_force(x):
    global EC_BACKEND_FORCE
    env_back = os.getenv('EC_BACKEND_FORCE')
    if env_back is not None:
        raise ValueError('Could not override Environment variable EC_BACKEND_FORCE')

    EC_BACKEND_FORCE = x



