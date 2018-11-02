
# Usage

Simple re-key all UTXO so the new seed can spend them:

```
./venv/bin/python -m monero_poc.tools.test_gen \
    --current 85148a19717a505fe4fc84219a79c4b4fdc35772ecb03b71385dc6572845d8096b8a47bdc2bd9923b1684abdbbed56a4e834b101011e4c28585ae1d01281030d \
    --dest 14821d0bc5659b24cafbc889dc4fc60785ee08b65d71c525f81eeaba4f3a570fa6ccd4ac344a295d1387f8d18c81bdd394f1845de84188e204514ef9370fd403 \
```


Re-keying + augmentation to use spend from sub-addresses and different major account number
(UTXO sent to account=2 and sub-addresses 2:0, 2:1, 2:2)

```
./venv/bin/python -m monero_poc.tools.test_gen \
    --current 85148a19717a505fe4fc84219a79c4b4fdc35772ecb03b71385dc6572845d8096b8a47bdc2bd9923b1684abdbbed56a4e834b101011e4c28585ae1d01281030d \
    --dest 14821d0bc5659b24cafbc889dc4fc60785ee08b65d71c525f81eeaba4f3a570fa6ccd4ac344a295d1387f8d18c81bdd394f1845de84188e204514ef9370fd403  \
    --desc --major 2 --suffix _sub --add-extra --minors 0 1 2 \
    --output /tmp  \
    monero_glue_test/data/tsx_t_uns_*
```

Augmentation:
 - Adds long payment ID
 - UTXO are received on minors
 - Mixin of sources is boosted to 12
 - 12 more outputs are added
 - 124 more UTXO are added

```
./venv/bin/python -m monero_poc.tools.test_gen
    --current 85148a19717a505fe4fc84219a79c4b4fdc35772ecb03b71385dc6572845d8096b8a47bdc2bd9923b1684abdbbed56a4e834b101011e4c28585ae1d01281030d \
    --dest 85148a19717a505fe4fc84219a79c4b4fdc35772ecb03b71385dc6572845d8096b8a47bdc2bd9923b1684abdbbed56a4e834b101011e4c28585ae1d01281030d \
    --desc --output /tmp/ \
    --minors 0 1 2 3 4 5 --add-long-nonce e8ce72659fbde7cc7c44871ca7784bba24b57323e66f7384ab06f2b8eea40649 \
    --mixin 12 --outs 12 --inputs 124 --suffix _mix11_inp128_out16 \
    monero_glue_test/data/tsx_t_uns_08_sub.txt
```
