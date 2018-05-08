# Proof of concept demo

PoC demonstrates spending implemented via signing protocol as described in the docs.
There are the following components:

- Trezor server, representing connected Trezor device. Isolated process, communicates over API.
- Trezor agent, host-based utility implementing host side of the  signing protocol.
- Agent spawns custom `monero-wallet-rpc`

This code relies on the watch-only features implemented to `monero-wallet-rpc`.
https://github.com/monero-project/monero/pull/3780

In case the code is not yet merged pls compile my fork:
https://github.com/ph4r05/monero/tree/ph4master

## Usage

- Generate wallet credentials on the first Trezor server start.
- Start agent, fetch watch-only credentials from Trezor.

Spending is then following:

- Generate unsigned transaction with agent
- Trezor agent (watch-only credentials) signs the transaction with Trezor server
- Submit signed transaction with the agent to the

## Submitting signed transaction

Key image sync feature is not yet implemented.

Python 3 is supported only (asyncio).

## Creating wallet

```bash
# Clone project
$> git clone https://github.com/ph4r05/monero-agent.git
$> cd monero-agent

# Install poc dependencies
$> pip install .[poc]
```

## Start Trezor server

For PoC there is standalone running Trezor HTTP server emulating Trezor device. It contains full wallet credentials
and communicates over HTTP according to the signing protocol described in the docs.

```bash
$> python3 -m monero_poc.trezor --account-file ./trezor.json --testnet --debug

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    Trezor server

    Account not initialized, call new_wallet
    Running on: 127.0.0.1:46123
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[trezor UNINIT]:
$>
```

Account file argument points to a file where the Trezor server stores all its information for consecutive executions.
It is created on the wallet initialization.

To use the PoC the wallet has to be generated. Call command `new_wallet`. It generates you a new Monero wallet in the
Trezor server.

```
[trezor UNINIT]: new_wallet
Generating new wallet...
Seed:             0x06655db21089b13c79449349867261962afd13b28b4b2e1862e4925430db56fe
Seed bip39 words: all cliff hold canal only owner topic mystery end crime observe clump quit mean sketch harvest come seek rice caution drink horror fossil siege
Seed bip32 b58:   xprv9s21ZrQH143K2M7Ln6c3KWpTxGkw5dfAuwveqeG88KeXb8G3uoJbo2RP85wGHLgqDXpHiXoDUkjo8bcxjk8f67QB8TR72BSVufgZRYXh6QJ
Seed Monero:      0x046d74151d684c2ed538373a614e2dfd4dd37c8a352757f7a1410b2a11484c3d
Seed Monero wrds: kept olive pylons semifinal nail ruined absorb iris pests because present plotting physics juicy zapped dexterity runway recipe lunar framed lair awning ardent fizzle

Spend key priv:   0x3df192fecd3e152652625051c56090be4dd37c8a352757f7a1410b2a11484c0d
View key priv:    0xdf04a2478b2502b2d971c0a65a43a2c744b07b297068cecc8c46e629cf2fd606

Spend key pub:    0x4f01f029ec771816dc42b0f7fbae228c25a00b0eca65b1562676bde4bb0797ca
View key pub:     0x9d8a70645c7a8a3321dfa66e80818015a6f25395027d08e25c6e5652c1947fb6

Address:          9vAJfX2DFLb4pmvES3v2KbQSbsRdYng8gFQmPb2kX2zAatd9C9AMNmo9Z3kwRQkXcs4d44jNpGp9uerzBJJBQEGnMeQSTMb
Wallet generated
[trezor 9vAJfX]:
```

Trezor wallet is now initialized and ready to use.

## Agent

In order to work with PoC running Agent is required.

The Agent spawns custom `monero-wallet-rpc` and keeps it running in the background. Agent terminates `monero-wallet-rpc`
on exit.

During the first start Agent loads watch-only credentials from the connected Trezor:

```
$> python3 -m monero_poc.agent --account-file agent.json \
    --watch-wallet /tmp/savvv \
    --monero-bin ~/workspace/monero/build/debug/bin/  \
    --rpc-addr 127.0.0.1:4808
Loading watch-only credentials from Trezor. Please, confirm the request on Trezor.
```

- `--account-file` represents state file for the Agent. It stores the state for the consecutive executions. The file
is created on the first start.
- `--watch-wallet` is the path to monero watch-only wallet that will be created by Agent. This key file can be
loaded by `monero-wallet-cli` and is used by `monero-wallet-rpc` spawned by agent
- `--rpc-addr 127.0.0.1:4808` enables to set address of monero full node.

Agent now tries to fetch watch-only credentials from the Trezor. Confirm the action on the Trezor:

```
--------------------------------------------------------------------------------
Watch-only request received
Enter W to confirm/reject
w
   1. Confirm
   2. Reject
Do you confirm sending watch-only credentials to the client? 1

2018-05-08 01:50:00 phx.local __main__[31865] INFO Returning watch only credentials...
[trezor 9vAJfX]:
```

After confirmation agent asks you for the wallet password file. The password will be used to protect monero watch only
wallet file.

```
Creating a new wallet. Please, enter the password:

Please enter the password again for verification:

Public spend key: 4f01f029ec771816dc42b0f7fbae228c25a00b0eca65b1562676bde4bb0797ca
Public view key : 9d8a70645c7a8a3321dfa66e80818015a6f25395027d08e25c6e5652c1947fb6
Address:          9vAJfX2DFLb4pmvES3v2KbQSbsRdYng8gFQmPb2kX2zAatd9C9AMNmo9Z3kwRQkXcs4d44jNpGp9uerzBJJBQEGnMeQSTMb
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    Monero Trezor agent

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

[wallet 9vAJfX]:
```

Now the agent is ready, check the balance:

```
[wallet 9vAJfX]: balance
Balance: 0.00000
Unlocked Balance: 0.00000
```

After sending some funds to this address you can see:

```
Balance: 315.00000
Unlocked Balance: 315.00000
[wallet 9vAJfX]:
```


### Security Note

Trezor and Agent configuration files are not protected / encrypted on purpose in the PoC. The idea is to give freedom
to work with JSON files (e.g, change to another address) if needed.

Note: For the PoC sake the communication between Trezor and Agent is serialized with `pickle`.
This is not secure as `pickle` is not immune to malformed / tampered archives. In the production a `protobuf`
messages will be constructed and use which are safe w.r.t. tampering.

# Spending

Spending is initiated in the Agent:

```
[wallet 9vAJfX]: transfer 9vacMKaj8JJV6MnwDzh2oNVdwTLJfTDyNRiB6NzV9TT7fqvzLivH2dB8Tv7VYR3ncn8vCb3KdNMJzQWrPAF1otYJ9cPKpkr 3.14159
Sending 3.14159 monero to 9vacMKaj8JJV6MnwDzh2oNVdwTLJfTDyNRiB6NzV9TT7fqvzLivH2dB8Tv7VYR3ncn8vCb3KdNMJzQWrPAF1otYJ9cPKpkr
Priority: default, mixin: default, payment_id: None
Do you confirm (y/n) ? y
2018-05-08 02:52:43 phx.local urllib3.connectionpool[42948] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-08 02:52:43 phx.local urllib3.connectionpool[42948] DEBUG http://127.0.0.1:48084 "POST /json_rpc HTTP/1.1" 401 98
2018-05-08 02:52:43 phx.local urllib3.connectionpool[42948] DEBUG http://127.0.0.1:48084 "POST /json_rpc HTTP/1.1" 200 5475
Fee: 0.00907699
Do you confirm (y/n) ? y
2018-05-08 02:52:44 phx.local urllib3.connectionpool[42948] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-08 02:52:44 phx.local urllib3.connectionpool[42948] DEBUG http://127.0.0.1:46123 "GET /api/v1.0/ping HTTP/1.1" 200 21
Signing transaction with Trezor
Please check the Trezor and confirm / reject the transaction

2018-05-08 02:52:44 phx.local __main__[42948] DEBUG Action: init_transaction
2018-05-08 02:52:44 phx.local urllib3.connectionpool[42948] DEBUG Starting new HTTP connection (1): 127.0.0.1
```

The transaction has to be now confirmed on the Trezor server in order to continue with the signature.

```
--------------------------------------------------------------------------------
Transaction confirmation procedure
Enter T to start

[trezor 9vAJfX|T?]: t
Confirming transaction:
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  Unlock time: 0
  UTXOs: 1
  Mixin: 7
  Output  0:   3.14159000 to 9vacMKaj8JJV6MnwDzh2oNVdwTLJfTDyNRiB6NzV9TT7fqvzLivH2dB8Tv7VYR3ncn8vCb3KdNMJzQWrPAF1otYJ9cPKpkr, sub: 0
  Change:    311.84933301 to 9vAJfX2DFLb4pmvES3v2KbQSbsRdYng8gFQmPb2kX2zAatd9C9AMNmo9Z3kwRQkXcs4d44jNpGp9uerzBJJBQEGnMeQSTMb, sub: 0
  Fee: 0.00907699
  Account: 0
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
   1. Confirm the transaction
   2. Reject
Do you confirm the transaction? 1

[trezor 9vAJfX]: 127.0.0.1 - - [08/May/2018 02:53:12] "POST /api/v1.0/tx_sign HTTP/1.1" 200 486 27.396638
(36839) accepted ('127.0.0.1', 54537)
2018-05-08 02:53:12 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Action: set_tsx_input
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Transaction step: 100, sub step: 0
127.0.0.1 - - [08/May/2018 02:53:12] "POST /api/v1.0/tx_sign HTTP/1.1" 200 736 0.076256
(36839) accepted ('127.0.0.1', 54538)
2018-05-08 02:53:12 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Action: set_tsx_output1
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Transaction step: 400, sub step: 0
127.0.0.1 - - [08/May/2018 02:53:14] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 1.884146
(36839) accepted ('127.0.0.1', 54539)
2018-05-08 02:53:14 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:14 phx.local __main__[36839] DEBUG Action: set_tsx_output1
2018-05-08 02:53:14 phx.local __main__[36839] DEBUG Transaction step: 400, sub step: 1
127.0.0.1 - - [08/May/2018 02:53:15] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 1.889318
(36839) accepted ('127.0.0.1', 54540)
2018-05-08 02:53:15 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Action: all_out1_set
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Transaction step: 500, sub step: None
127.0.0.1 - - [08/May/2018 02:53:15] "POST /api/v1.0/tx_sign HTTP/1.1" 200 792 0.007530
(36839) accepted ('127.0.0.1', 54541)
2018-05-08 02:53:15 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Action: tsx_mlsag_done
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Transaction step: 600, sub step: None
127.0.0.1 - - [08/May/2018 02:53:15] "POST /api/v1.0/tx_sign HTTP/1.1" 200 402 0.014496
(36839) accepted ('127.0.0.1', 54542)
2018-05-08 02:53:16 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:16 phx.local __main__[36839] DEBUG Action: sign_input
2018-05-08 02:53:16 phx.local __main__[36839] DEBUG Transaction step: 700, sub step: None
127.0.0.1 - - [08/May/2018 02:53:16] "POST /api/v1.0/tx_sign HTTP/1.1" 200 1725 0.546059
(36839) accepted ('127.0.0.1', 54543)
2018-05-08 02:53:16 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:16 phx.local __main__[36839] DEBUG Action: final
--------------------------------------------------------------------------------
Transaction was successfully signed
127.0.0.1 - - [08/May/2018 02:53:17] "POST /api/v1.0/tx_sign HTTP/1.1" 200 640 0.937941
```

The Agent asks one more time whether to submit:

```
Key images: ['9ffe8e711168dda05570882bf3650e9f405832053427582527c55cd4fe8024c9']
Transaction has been signed.
Do you wish to submit (y/n) ? y
2018-05-08 02:53:43 phx.local urllib3.connectionpool[42948] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-08 02:53:43 phx.local urllib3.connectionpool[42948] DEBUG http://127.0.0.1:48084 "POST /json_rpc HTTP/1.1" 401 98
2018-05-08 02:53:43 phx.local urllib3.connectionpool[42948] DEBUG http://127.0.0.1:48084 "POST /json_rpc HTTP/1.1" 200 149
SUCCESS: Transaction has been submitted!
```

# Spending - with monero-wallet-cli

This is the old way of spending using `monero-wallet-cli`.
The monero wallet key file generated by agent can be opened by `monero-wallet-cli` so user can perform
additional tasks not yet implemented in the Agent.

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


