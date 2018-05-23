# Monero Wallet Python implementation

[![Build Status](https://travis-ci.org/ph4r05/monero-agent.svg?branch=master)](https://travis-ci.org/ph4r05/monero-agent)

Pure-python Monero Wallet implementation in Python3.
Supports RingCT signature on the given Transaction Construction Data.

## Work in progress

This work is still in progress. The project is initial implementation version.
It may contain bugs and the EC crypto operations are not constant-time as it serves mainly as PoC at the moment.

Moreover, the code will probably be subject to a major refactoring and cleaning.

## Supported features

 - Full RingCT (one UTXO)
 - Simple RingCT (more than 1 UTXOs)
 - Sub-addresses
 - Key image sync

## Roadmap

 - Tests 
 - Multisig
 - Spend proofs
 - Wallet implementation (funds receiving, UTXO mixing)

## Protocol

In order to support RingCT on hardware wallet with limited resources a subdivided protocol had to be implemented.
It is not feasible to process the signed transaction in one run on the hardware wallet with tens of UTXOs and multiple outputs.

The introduction to the topic is described here:

https://github.com/ph4r05/monero-trezor-doc

The documentation can be out of sync from the code. Take this source code as a primary reference.

In the current protocol it is assumed there may be multiple input UTXO (tens to hundreds). So it is optimized
to work incrementally, one UTXO at a time. This is reasonable to assume as your funds may be scattered over
many small transactions. On the other hand we assume the number of outputs is relatively small (small units) as
it usually is in the Monero transactions.

It is quite easy to extend protocol to work with large amounts of outputs but due to the message structure
which is later signed it will be needed to add two more roundrips with sending output related data one by one
to the Trezor for incremental hashing.

Outputs are pinned in the beginning of the protocol - number of outputs is fixed at this point in the Trezor
and HMAC with unique key (index dependent) is generated for each output. So in further roundtrips it is assured only
previously pinned outputs in the exact given order are processed. The same principle is used for each data produced by
the Trezor which are later used as inputs.

## Project structure

Agent <-> Trezor

Agent is an object supposed to run on the host PC where Trezor is the HW wallet implementation.
`agent.py` and `trezor.py` are mainly ports of the C++ code to the Python for PoC, experimentation and testing.
These versions are not optimized for usage in HW environment.

Optimized versions are `agent_lite.py` and `trezor_lite.py`.

## Serialize lib

The project depends on my `monero-serialize` library.
Data objects used in the Monero are defined there, it supports serialization / deserialization to binary format.
The serialized binary messages are hashed during the transaction signature.

https://github.com/ph4r05/monero-serialize

## Crypto

Monero uses Ed25519 elliptic curve. The current implementation is not optimized to avoid side-channel leaks (e.g., timing)
as it serves mainly as PoC.

The project has multiple Ed25519 implementations. One works with the normal coordinates `(x, y)` the other
works in extended Edwards coordinates `(x, y, z, t)`. The primary representation used is extended Edwards.
It is possible to switch between these two implementations. Please note a point is not represented
in an unique way in extended coordinates and point comparisson has to be done via `crypto.point_eq()` method.

The only code directly handling point representation is `crypto.py`. All other objects are using `crypto.py`
to do the EC computation. Point representation is opaque to the other modules.

The opaque point representation can be converted to bytearray representation suitable for transport
(compressed, y-coordinate + sign flag) using `crypto.encodepoint()` and `crypto.decodepoint()`.

Scalars are represented as integers (no encoding / decoding is needed). However, we are working in modular ring so
for scalar operations such as addition, division, comparison use the `crypto.sc_*` methods.

## Trezor-crypto

A new crypto backend was added, `trezor-crypto`.
I implemented missing cryptographic algorithms to the [trezor-crypto], branch `lib` (abbrev. TCRY).
Compiled shared library `libtrezor-crypto.so` can be used instead of the Python crypto backend.
TCRY implements constant-time curve operations, uses [libsodium] to generate random values.

Range proof was reimplemented in C for CPU and memory efficiency.

Travis tests with both crypto backends. In order to test with TCRY install all its dependencies. `libsodium` is the only one
dependency for the shared lib. For more info take a look at `travis-install-libtrezor-crypto.sh`.

Crypto dependency is selected based on the `EC_BACKEND` env var. `0` is for Python backend, `1` for TCRY.
Path to the TCRY is specified via `LIBTREZOR_CRYPTO_PATH` env var. If the TCRY is not found or could not be loaded
the code fallbacks to python backend. This behaviour can be changed by setting `EC_BACKEND_FORCE` env var to `1`.

TCRY is also 20 times faster (unit tests).

```bash
$> EC_BACKEND=0 ./venv/bin/python3 -m unittest discover
.....................................................
----------------------------------------------------------------------
Ran 53 tests in 142.363s

OK
```

TCRY backend:

```bash
$> LIBTREZOR_CRYPTO_PATH="$HOME/libtrezor-crypto/libtrezor-crypto.so" EC_BACKEND_FORCE=1 EC_BACKEND=1 \
    ./venv/bin/python3 -m unittest discover
.....................................................
----------------------------------------------------------------------
Ran 53 tests in 7.252s

OK
```

UPDATE: I created a python binding [py-trezor-crypto] which can be installed from pip. The pip builds [trezor-crypto]
library. Please refer to the readme of the [py-trezor-crypto] for installation details (dependencies).

To install python bindings with agent run:

```bash
pip install monero_agent[tcry]
```

Libsodium, pkg-config, gcc, python-dev are required for the installation.

### Memory considerations

Python uses arbitrary precision integers with a memory overhead.
The following command shows the amount of memory required for certain data types and sizes:

```python
>>> sys.getsizeof(0)
24
>>> sys.getsizeof(2**32-1)  # 4B num
32
>>> sys.getsizeof(2**64-1)  # 8B num
36
>>> sys.getsizeof(2**256-1)  # 32B num
60
>>> sys.getsizeof(b'\x00'*32)  # 32B hex
65
>>> sys.getsizeof(b'\x00'*64)  # 64B hex
97
```

Monero works in EC with 32 B numbers.
To store a 32 B number it takes 60 B in integer representation and 65 B in the byte string encoded
representation (some ed25519 libraries and mininero use this representation).
For scalars it is apparently more effective to store integers naturally, saving both memory and CPU cycles with recoding.

EC point arithmetics can use classic point coordinates `(x, y)` or extended Edwards point coordinates `(x,y,z,t)`.
It takes 64 and 80 B to store tuple of 2 and 4 elements respectively.
It thus take 184 B and 320 B to store an EC point in the natural form compared to the 65 B byte representation.


[trezor-crypto]: https://github.com/ph4r05/trezor-crypto
[libsodium]: https://github.com/jedisct1/libsodium
[py-trezor-crypto]: https://github.com/ph4r05/py-trezor-crypto

