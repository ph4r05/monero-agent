#!/bin/bash
pip install .[dev]

# trezor-crypto backend
EC_BACKEND_FORCE=1 EC_BACKEND=1 python -m unittest discover $*


# python backend
EC_BACKEND=0 python -m unittest discover $*
