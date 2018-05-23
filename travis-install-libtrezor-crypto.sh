#!/bin/sh
# libsodium-dev replacement
#
# The purpose of this file is to install libsodium in
# the Travis CI environment. Outside this environment,
# you would probably not want to install it like this.

set -e
export RELEASE_NAME="lib_v0.0.9"

# check if libsodium is already installed
#if [ ! -d "$HOME/libtrezor-crypto/lib" ]; then
  wget "https://github.com/ph4r05/trezor-crypto/archive/${RELEASE_NAME}.tar.gz"
  tar xvfz "${RELEASE_NAME}.tar.gz"
  cd "trezor-crypto-${RELEASE_NAME}"
  make lib
  cp libtrezor-crypto.so "$HOME/libtrezor-crypto/"

#else
#  echo 'Using cached directory.'
#fi
