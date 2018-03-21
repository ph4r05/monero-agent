#!/bin/bash
pip install .[dev]
python -m unittest discover $*
