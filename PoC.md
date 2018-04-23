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

Python 3 is supported only (asyncio).

## Creating wallet

```bash
# Install poc dependencies
$> git clone https://github.com/ph4r05/monero-agent.git
$> cd monero-agent
$> pip install .[poc]

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

# Spending

In order to spend pls send funds to address you just created.

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
$> python -m monero_poc.agent \
    --address 9sj6vz6uiX9dYekg1SWHzWViba8qLZA2mGmjTbR9QFNshk3bxruqQH3VrHprg2Pw4AitgRxnSpZkugJHWoB6YQYc8PgWp5X \
    --view-key 41db4ed31316f25ac932fe9c4ba820da7e8740f695148719bf0948848faa5c08 \
    --sign ~/testnet/unsigned_monero_tx --debug

Ver: 53
Public spend key: 0ec3b9d85be168da7e144476d7ae9fabb052b3a8d6841a5e4a43ba4ac40984f3
Public view key : 94d7cda144c0feac7b5b160fa617effa733aaebf3d3c3aeaf28d14006f4fcd41
2018-04-23 13:02:35 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:02:35 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "GET /api/v1.0/ping HTTP/1.1" 200 21
Signing transaction with Trezor
Please check the Trezor and confirm / reject the transaction

2018-04-23 13:02:35 phx.local __main__[33126] DEBUG Action: init_transaction
2018-04-23 13:02:35 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
```

## Confirm the transaction on Trezor

Trezor server will asks you to start transaction confirmation.
To start confirmation enter command "T".

```
--------------------------------------------------------------------------------
Transaction confirmation procedure
Enter T to start

$> t
Confirming transaction:
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  Unlock time: 0
  UTXOs: 1
  Mixin: 7
  Output  0:  16.00000000 to 9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8, sub: 0
  Change:    546.95380931 to 9sj6vz6uiX9dYekg1SWHzWViba8qLZA2mGmjTbR9QFNshk3bxruqQH3VrHprg2Pw4AitgRxnSpZkugJHWoB6YQYc8PgWp5X, sub: 0
  Fee: 0.00908518
  Account: 0
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
   1. Confirm the transaction
   2. Reject
Do you confirm the transaction?


$> 127.0.0.1 - - [23/Apr/2018 13:04:05] "POST /api/v1.0/tx_sign HTTP/1.1" 200 486 89.632906
(32890) accepted ('127.0.0.1', 55156)
2018-04-23 13:04:05 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:05 phx.local __main__[32890] DEBUG Action: set_tsx_input
2018-04-23 13:04:05 phx.local __main__[32890] DEBUG Transaction step: 100, sub step: 0
127.0.0.1 - - [23/Apr/2018 13:04:05] "POST /api/v1.0/tx_sign HTTP/1.1" 200 736 0.055637
(32890) accepted ('127.0.0.1', 55157)
2018-04-23 13:04:05 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:05 phx.local __main__[32890] DEBUG Action: set_tsx_output1
2018-04-23 13:04:05 phx.local __main__[32890] DEBUG Transaction step: 400, sub step: 0
127.0.0.1 - - [23/Apr/2018 13:04:06] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 1.762697
(32890) accepted ('127.0.0.1', 55158)
2018-04-23 13:04:06 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:06 phx.local __main__[32890] DEBUG Action: set_tsx_output1
2018-04-23 13:04:06 phx.local __main__[32890] DEBUG Transaction step: 400, sub step: 1
127.0.0.1 - - [23/Apr/2018 13:04:09] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 2.046899
(32890) accepted ('127.0.0.1', 55159)
2018-04-23 13:04:09 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Action: all_out1_set
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Transaction step: 500, sub step: None
127.0.0.1 - - [23/Apr/2018 13:04:09] "POST /api/v1.0/tx_sign HTTP/1.1" 200 792 0.007873
(32890) accepted ('127.0.0.1', 55160)
2018-04-23 13:04:09 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Action: tsx_mlsag_done
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Transaction step: 600, sub step: None
127.0.0.1 - - [23/Apr/2018 13:04:09] "POST /api/v1.0/tx_sign HTTP/1.1" 200 402 0.015414
(32890) accepted ('127.0.0.1', 55161)
2018-04-23 13:04:09 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Action: sign_input
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Transaction step: 700, sub step: None
127.0.0.1 - - [23/Apr/2018 13:04:09] "POST /api/v1.0/tx_sign HTTP/1.1" 200 1725 0.528009
(32890) accepted ('127.0.0.1', 55162)
2018-04-23 13:04:09 phx.local asyncio[32890] DEBUG Using selector: KqueueSelector
2018-04-23 13:04:09 phx.local __main__[32890] DEBUG Action: final
--------------------------------------------------------------------------------
Transaction was successfully signed
```

## Check the agent

After confirming the transaction agent should produce the following output:

```
2018-04-23 13:04:05 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 353
2018-04-23 13:04:05 phx.local __main__[33126] DEBUG Req size: 859, response size: 157
2018-04-23 13:04:05 phx.local __main__[33126] DEBUG Action: set_tsx_input
2018-04-23 13:04:05 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:05 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 603
2018-04-23 13:04:05 phx.local __main__[33126] DEBUG Req size: 1485, response size: 282
2018-04-23 13:04:05 phx.local __main__[33126] DEBUG Action: set_tsx_output1
2018-04-23 13:04:05 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:06 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 15333
2018-04-23 13:04:06 phx.local __main__[33126] DEBUG Req size: 385, response size: 7647
2018-04-23 13:04:06 phx.local __main__[33126] DEBUG Action: set_tsx_output1
2018-04-23 13:04:06 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 15333
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Req size: 386, response size: 7647
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Action: all_out1_set
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 659
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Req size: 10, response size: 310
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Action: tsx_mlsag_done
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 269
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Req size: 10, response size: 115
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Action: sign_input
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 1591
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Req size: 1677, response size: 776
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Action: final
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-04-23 13:04:09 phx.local urllib3.connectionpool[33126] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 47
2018-04-23 13:04:09 phx.local __main__[33126] DEBUG Req size: 10, response size: 4
2018-04-23 13:04:10 phx.local __main__[33126] INFO Signed transaction file: signed_monero_tx
Key images: ['0d87342578157e587c837c803ac3f50152522a74c7ad10225e54d730355e73c0', '5ee6acafe99c4d73ef4ba20252953eb3b3493356d6d6cbe1ff2b31163558732f', 'e1f644522c831cafe1e100e98133535e85d9e73d886b209b987d5b07de040425', '52d65922cf28ae7086effd5f1058fd18867f381e9cfc5a38cf44b044c0ca4a28', '6b9b5bb1e9b14651ecedd6990d9e88bf1ecc18a05ed23b9ea01aa749825e7fab', '38687837f1099f96d1c43b2d29765ddf15513d1e05ad7630d8302aa5cb3d7690']
Transaction 00 stored to transaction_00, relay script: transaction_00_relay.sh
Please note that by manual relaying hot wallet key images get out of sync
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


