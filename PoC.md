# Proof of concept demo

- Generate wallet credentials
- Create watch-only wallet
- Start Trezor server with full credentials (represents running Trezor device)

Spending is then following:

- Generate unsigned transaction with watch-only wallet
- Use Trezor agent with view-only credentials to sign the transaction with Trezor server
- Submit signed transaction with watch only wallet

## Submitting signed transaction

Note the submit has to be done with hot watch-only wallet otherwise key images will get out of sync.
Key image sync feature is not yet implemented.

## Creating wallet

```bash
# Install poc dependencies
$> pip install monero-agent[poc]

$> cd monero-agent/
$> python -m monero_poc.generate_creds --testnet
Address: 9wzrQmYBPcL2SdHrZhURPhQQeeYAriuv4FSKsqqRRpBaMsknACiLjyrLtTpdToGYh2ao9jFMcKzwUUgg3ZChvPXX75Gfifc
Private view key:  53ebe2f7c79b1cf7fab2d7d049700b2c73497ff5d83b8445fb5fa72e6d01db03
Private spend key: d074ddf0e1e843f13b5e48a42a7aa6c6afa79a87c91c840882c466e67fd18207
```

## Create watch only wallet:

```bash
$> monero-wallet-cli --testnet --generate-from-view-key wallet_file
Standard address: 9wzrQmYBPcL2SdHrZhURPhQQeeYAriuv4FSKsqqRRpBaMsknACiLjyrLtTpdToGYh2ao9jFMcKzwUUgg3ZChvPXX75Gfifc
View key: 53ebe2f7c79b1cf7fab2d7d049700b2c73497ff5d83b8445fb5fa72e6d01db03
```

Later the watch-only wallet can be opened in the following way:

```bash
monero-wallet-cli --testnet --wallet-file wallet_file
```

## Start Trezor server

For PoC there is standalone running Trezor HTTP server emulating Trezor device. It contains full wallet credentials
and communicates over HTTP according to the signing protocol described in the docs.

```bash
$> python -m monero_poc.trezor \
      --view-key 41db4ed31316f25ac932fe9c4ba820da7e8740f695148719bf0948848faa5c08 \
      --spend-key edef56d734c77b8bbfbfb36774580bc4c5c2f00937322a4a289f1cdccb5df506 \
      --testnet

--------------------------------------------------------------------------------------------------------------------------------
    Trezor server

    Account address: 9sj6vz6uiX9dYekg1SWHzWViba8qLZA2mGmjTbR9QFNshk3bxruqQH3VrHprg2Pw4AitgRxnSpZkugJHWoB6YQYc8PgWp5X
    Running on: 127.0.0.1:46123
--------------------------------------------------------------------------------------------------------------------------------
$>
```

Note: For the PoC sake the communication between Trezor and Agent is serialized with `pickle`.
This is not secure as `pickle` is not immune to malformed / tampered archives. In the production a `protobuf`
messages will be constructed and use which are safe w.r.t. tampering.

## Create unsigned transaction

In the watch only hot wallet:

```
[wallet 9sj6vz]: transfer 9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8 16
Wallet password:
No payment id is included with this transaction. Is this okay?  (Y/Yes/N/No): y

Transaction 1/1:
Spending from address index 0
Sending 16.000000000000.  The transaction fee is 0.009098180000
Is this okay?  (Y/Yes/N/No): y
Unsigned transaction(s) successfully written to file: unsigned_monero_tx
```

## Sign the transaction

Use Agent to perform signing protocol with the Trezor.

```bash
$> ./venv/bin/python3 -m monero_poc.agent \
    --address 9sj6vz6uiX9dYekg1SWHzWViba8qLZA2mGmjTbR9QFNshk3bxruqQH3VrHprg2Pw4AitgRxnSpZkugJHWoB6YQYc8PgWp5X \
    --view-key 41db4ed31316f25ac932fe9c4ba820da7e8740f695148719bf0948848faa5c08 \
    --sign ~/testnet/unsigned_monero_tx

2018-04-23 01:28:15 phx.local asyncio[9461] DEBUG Using selector: KqueueSelector
Ver: 53
Public spend key: 0ec3b9d85be168da7e144476d7ae9fabb052b3a8d6841a5e4a43ba4ac40984f3
Public view key : 94d7cda144c0feac7b5b160fa617effa733aaebf3d3c3aeaf28d14006f4fcd41
2018-04-23 01:28:16 phx.local __main__[9461] DEBUG Action: init_transaction
2018-04-23 01:28:16 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:16 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 207
2018-04-23 01:28:16 phx.local __main__[9461] DEBUG Req size: 859, response size: 84
2018-04-23 01:28:16 phx.local __main__[9461] DEBUG Action: set_tsx_input
2018-04-23 01:28:16 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:16 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 453
2018-04-23 01:28:16 phx.local __main__[9461] DEBUG Req size: 1485, response size: 207
2018-04-23 01:28:16 phx.local __main__[9461] DEBUG Action: set_tsx_output1
2018-04-23 01:28:16 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:17 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 15187
2018-04-23 01:28:17 phx.local __main__[9461] DEBUG Req size: 385, response size: 7574
2018-04-23 01:28:17 phx.local __main__[9461] DEBUG Action: set_tsx_output1
2018-04-23 01:28:17 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:19 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 15187
2018-04-23 01:28:19 phx.local __main__[9461] DEBUG Req size: 386, response size: 7574
2018-04-23 01:28:19 phx.local __main__[9461] DEBUG Action: all_out1_set
2018-04-23 01:28:19 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:19 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 513
2018-04-23 01:28:19 phx.local __main__[9461] DEBUG Req size: 10, response size: 237
2018-04-23 01:28:19 phx.local __main__[9461] DEBUG Action: tsx_mlsag_done
2018-04-23 01:28:19 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:19 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 117
2018-04-23 01:28:19 phx.local __main__[9461] DEBUG Req size: 10, response size: 39
2018-04-23 01:28:19 phx.local __main__[9461] DEBUG Action: sign_input
2018-04-23 01:28:19 phx.local urllib3.connectionpool[9461] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 01:28:20 phx.local urllib3.connectionpool[9461] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 1445
2018-04-23 01:28:20 phx.local __main__[9461] DEBUG Req size: 1675, response size: 703
2018-04-23 01:28:20 phx.local __main__[9461] INFO Signed transaction file: signed_monero_tx
Key images: ['0d87342578157e587c837c803ac3f50152522a74c7ad10225e54d730355e73c0', '5ee6acafe99c4d73ef4ba20252953eb3b3493356d6d6cbe1ff2b31163558732f', 'e1f644522c831cafe1e100e98133535e85d9e73d886b209b987d5b07de040425', '52d65922cf28ae7086effd5f1058fd18867f381e9cfc5a38cf44b044c0ca4a28', '6b9b5bb1e9b14651ecedd6990d9e88bf1ecc18a05ed23b9ea01aa749825e7fab']
Transaction 00 stored to transaction_00, relay script: transaction_00_relay.sh
Please note that by manual relaying hot wallet key images get out of sync
2018-04-23 01:28:20 phx.local __main__[9461] INFO Terminating
```

## Submit transfer

Use watch only hot wallet to submit signed transaction. This step performs also key image synchronisation so
hot wallet is able to construct new transactions, otherwise it could construct invalid transactions
without knowing which UTXOs have been spent which leads to double spending error.

Place `signed_monero_tx` file produced by the Agent to the running directory of the wallet.

```
[wallet 9sj6vz]: submit_transfer
Loaded 1 transactions, for 574.971992670000, fee 0.009098180000, sending 16.000000000000 to 9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8, 558.962894490000 change to 9sj6vz6uiX9dYekg1SWHzWViba8qLZA2mGmjTbR9QFNshk3bxruqQH3VrHprg2Pw4AitgRxnSpZkugJHWoB6YQYc8PgWp5X, with min ring size 7, no payment ID. 5 key images to import. Is this okay? (Y/Yes/N/No): y
Transaction successfully submitted, transaction <3193ace53d1f67b9773426b9c954cf500f6041bea97654e3dd1a5e565e96dbf7>
You can check its status by using the `show_transfers` command.
```


