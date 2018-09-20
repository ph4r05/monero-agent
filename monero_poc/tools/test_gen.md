

```
./venv/bin/python -m monero_poc.tools.test_gen \
    --current 85148a19717a505fe4fc84219a79c4b4fdc35772ecb03b71385dc6572845d8096b8a47bdc2bd9923b1684abdbbed56a4e834b101011e4c28585ae1d01281030d \
    --dest 14821d0bc5659b24cafbc889dc4fc60785ee08b65d71c525f81eeaba4f3a570fa6ccd4ac344a295d1387f8d18c81bdd394f1845de84188e204514ef9370fd403 \
```

```
./venv/bin/python -m monero_poc.tools.test_gen \
    --current 85148a19717a505fe4fc84219a79c4b4fdc35772ecb03b71385dc6572845d8096b8a47bdc2bd9923b1684abdbbed56a4e834b101011e4c28585ae1d01281030d \
    --dest 14821d0bc5659b24cafbc889dc4fc60785ee08b65d71c525f81eeaba4f3a570fa6ccd4ac344a295d1387f8d18c81bdd394f1845de84188e204514ef9370fd403  \
    --desc --major 2 --suffix _sub --add-extra --minors 0 1 2 \
    --output /tmp  \
    monero_glue_test/data/tsx_t_uns_*
```
