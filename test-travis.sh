#!/bin/bash
pip install .[dev]

# trezor-crypto backend
# EC_BACKEND_FORCE=1 EC_BACKEND=1 python -m unittest discover $*
EC_BACKEND_FORCE=1 EC_BACKEND=1 python -m unittest monero_glue_test/test_*.py


# python backend
# EC_BACKEND=0 python -m unittest discover $*
EC_BACKEND=0 SKIP_TREZOR_TSX=1 python -m unittest monero_glue_test/test_*.py
