#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import logging
from . import ec_picker


logger = logging.getLogger(__name__)
backend = ec_picker.get_ec_backend()


if backend == ec_picker.EC_BACKEND_PY:
    from monero_glue.xmr.core.ec_py import *

elif backend == ec_picker.EC_BACKEND_TREZOR:
    try:
        from monero_glue.xmr.core.ec_trezor import *
        
    except Exception as e:
        logger.warning('Trezor-crypto backend not usable: %s' % e)
        if ec_picker.get_ec_backend_force():
            raise

        from monero_glue.xmr.core.ec_py import *

else:
    raise ValueError('Unknown EC backend: %s' % backend)

