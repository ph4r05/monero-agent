# Monero Wallet Python implementation

Pure-python Monero Wallet implementation in Python3.
Supports RingCT signature on the given Transaction Construction Data.

## Work in progress

This work is still in progress.
It may contain bugs and the EC crypto operations are not constant-time as it serves mainly as PoC at the moment.

Moreover, the code will probably be subject to a major refactoring and cleaning.

## Supported features

 - Full RingCT (one UTXO)
 - Simple RingCT (more than 1 UTXOs)
 - Sub-addresses

## Roadmap

 - Multisig
 - Spend proofs
 - Wallet implementation (funds receiving, UTXO mixing)

## Protocol

In order to support RingCT on hardware wallet with limited resources a subdivided protocol had to be implemented.
It is not feasible to process the signed transaction in one run on the hardware wallet with tens of UTXOs and multiple outputs.

The introduction to the topic is described here:

https://github.com/ph4r05/monero-trezor-doc

The documentation can be out of sync from the code. Take this source code as a primary reference.

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

EC point arithmetics can use classic point coordinates $(x, y)$ or extended Edwards point coordinates $(x,y,z,t)$.
It takes 64 and 80 B to store tuple of 2 and 4 elements respectively.
It thus take 184 B and 320 B to store an EC point in the natural form compared to the 65 B byte representation.


