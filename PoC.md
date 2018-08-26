# Proof of concept demo

PoC demonstrates spending implemented via signing protocol as described in the docs.
There are the following components:

- Trezor server, representing connected Trezor device. Isolated process, communicates over API.
- Trezor agent, host-based utility implementing host side of the  signing protocol.
- Agent spawns custom `monero-wallet-rpc`

This code relies on the watch-only features implemented to `monero-wallet-rpc`.

https://github.com/monero-project/monero/pull/3780


PR is already merged but should you need any more unmerged features here is my fork:

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

Trezor configuration files are not protected / encrypted on purpose in the PoC. The idea is to give freedom
to work with JSON files (e.g, change to another address) if needed.

Note: For the PoC sake some communication between Trezor and Agent is serialized with `pickle`.
This is not secure as `pickle` is not immune to malformed / tampered archives. In the production a `protobuf`
messages will be constructed and use which are safe w.r.t. tampering.

Transaction signing and key image sync protocol are already transformed to the protocol message form.

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

2018-05-08 02:52:44 phx.local __main__[42948] DEBUG Action: tsx_init
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
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Action: tsx_set_input
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Transaction step: 100, sub step: 0
127.0.0.1 - - [08/May/2018 02:53:12] "POST /api/v1.0/tx_sign HTTP/1.1" 200 736 0.076256
(36839) accepted ('127.0.0.1', 54538)
2018-05-08 02:53:12 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Action: tsx_set_output1
2018-05-08 02:53:12 phx.local __main__[36839] DEBUG Transaction step: 400, sub step: 0
127.0.0.1 - - [08/May/2018 02:53:14] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 1.884146
(36839) accepted ('127.0.0.1', 54539)
2018-05-08 02:53:14 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:14 phx.local __main__[36839] DEBUG Action: tsx_set_output1
2018-05-08 02:53:14 phx.local __main__[36839] DEBUG Transaction step: 400, sub step: 1
127.0.0.1 - - [08/May/2018 02:53:15] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 1.889318
(36839) accepted ('127.0.0.1', 54540)
2018-05-08 02:53:15 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Action: tsx_all_out1_set
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Transaction step: 500, sub step: None
127.0.0.1 - - [08/May/2018 02:53:15] "POST /api/v1.0/tx_sign HTTP/1.1" 200 792 0.007530
(36839) accepted ('127.0.0.1', 54541)
2018-05-08 02:53:15 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Action: tsx_mlsag_done
2018-05-08 02:53:15 phx.local __main__[36839] DEBUG Transaction step: 600, sub step: None
127.0.0.1 - - [08/May/2018 02:53:15] "POST /api/v1.0/tx_sign HTTP/1.1" 200 402 0.014496
(36839) accepted ('127.0.0.1', 54542)
2018-05-08 02:53:16 phx.local asyncio[36839] DEBUG Using selector: KqueueSelector
2018-05-08 02:53:16 phx.local __main__[36839] DEBUG Action: tsx_sign_input
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
[wallet 9yBfm6]: transfer 7 9twQxUpHzXrQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB7ufnmk 1.9
Wallet password:
No payment id is included with this transaction. Is this okay?  (Y/Yes/N/No): y

Transaction 1/1:
Spending from address index 0
Sending 1.900000000000.  The transaction fee is 0.009759120000
Transaction 1/1: txid=<e2c732b158a0f7edd5e9de0bd095d0a89b8e93c67caf231fbb6fa987e8dded7e>
Input 1/2: amount=95.922799320000
Originating block heights:  3801 4074 7645 8097 8729 9595 *9744
|______________________________o_o___________________________o___o____o______o*_|

Input 2/2: amount=1.100000000000
Originating block heights:  8808 8890 9066 *9370 9622 9630 9778
|______________________________________________________________________o_o_*_o_o|


Is this okay?  (Y/Yes/N/No): y
Unsigned transaction(s) successfully written to file: unsigned_monero_tx
```

## Sign the transaction

Use Agent to perform signing protocol with the Trezor. The agent support either command `sign` from the CLI interface
as shown in the previous example or via params:

```bash
$> python -m monero_poc.agent \
    --account-file agent.json \
    --sign ~/testnet/unsigned_monero_tx \
    --debug

Please, enter the wallet password:

Public spend key: 9ecb062f3dd9416f111279f379714867db08963b83e89cab9bdb26a27982f2d6
Public view key : 39b1b8c7ecffcdd6817f0592349df0b38414540e0a6fcd0847b5fa2c0d814c78
Address:          9yBfm6wd3beKaVBv3BU9SfJNXhwksKMByVhpazXFS6TKcqFksNUZHtpcsyaDheNq1RX2Xi3WQMhx82PKzrB6pTm5Ebu3Dgb
2018-05-15 21:42:06 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:06 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "GET /api/v1.0/ping HTTP/1.1" 200 21
Signing transaction with Trezor
Please check the Trezor and confirm / reject the transaction

2018-05-15 21:42:07 phx.local __main__[20798] DEBUG Action: tsx_init
2018-05-15 21:42:07 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
```

## Confirm the transaction on Trezor

Trezor server will asks you to start transaction confirmation.
To start confirmation enter command "T".

```
--------------------------------------------------------------------------------
Transaction confirmation procedure
Enter T to start
t
Confirming transaction:
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  Unlock time: 0
  UTXOs: 2
  Mixin: 7
  Output  0:   1.90000000 to 9twQxUpHzXrQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB7ufnmk, sub: 0
  Change:     95.11304020 to 9yBfm6wd3beKaVBv3BU9SfJNXhwksKMByVhpazXFS6TKcqFksNUZHtpcsyaDheNq1RX2Xi3WQMhx82PKzrB6pTm5Ebu3Dgb, sub: 0
  Fee: 0.00975912
  Account: 0
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
   1. Confirm the transaction
   2. Reject
Do you confirm the transaction? 1

[trezor 9yBfm6]: 127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 486 13.264746
(18494) accepted ('127.0.0.1', 63637)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_set_input
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 100, sub step: 0
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 1034 0.006508
(18494) accepted ('127.0.0.1', 63638)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_set_input
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 100, sub step: 1
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 1026 0.007608
(18494) accepted ('127.0.0.1', 63639)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_inputs_permutation
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 200, sub step: None
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 332 0.001828
(18494) accepted ('127.0.0.1', 63640)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_input_vini
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 300, sub step: 0
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 332 0.006787
(18494) accepted ('127.0.0.1', 63641)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_input_vini
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 300, sub step: 1
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 332 0.004619
(18494) accepted ('127.0.0.1', 63642)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_set_output1
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 400, sub step: 0
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 0.066715
(18494) accepted ('127.0.0.1', 63643)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_set_output1
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 400, sub step: 1
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 15468 0.066210
(18494) accepted ('127.0.0.1', 63644)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_all_out1_set
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 500, sub step: None
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 792 0.002638
(18494) accepted ('127.0.0.1', 63645)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_mlsag_done
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 600, sub step: None
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 402 0.002878
(18494) accepted ('127.0.0.1', 63646)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_sign_input
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 700, sub step: None
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 1725 0.017701
(18494) accepted ('127.0.0.1', 63647)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: tsx_sign_input
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction step: 700, sub step: None
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Transaction signed
127.0.0.1 - - [15/May/2018 21:42:20] "POST /api/v1.0/tx_sign HTTP/1.1" 200 1725 0.018710
(18494) accepted ('127.0.0.1', 63648)
2018-05-15 21:42:20 phx.local asyncio[18494] DEBUG Using selector: KqueueSelector
2018-05-15 21:42:20 phx.local __main__[18494] DEBUG Action: final
--------------------------------------------------------------------------------
Transaction was successfully signed
```

## Check the agent

After confirming the transaction agent should produce the following output:

```
2018-05-15 21:42:07 phx.local __main__[20798] DEBUG Action: tsx_init
2018-05-15 21:42:07 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 353
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 930, response size: 157
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_set_input
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 901
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 1484, response size: 431
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_set_input
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 893
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 1484, response size: 427
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_inputs_permutation
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 199
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 21, response size: 80
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_input_vini
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 199
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 1746, response size: 80
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_input_vini
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 199
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 1742, response size: 80
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_set_output1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 15333
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 385, response size: 7647
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_set_output1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 15333
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 385, response size: 7647
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_all_out1_set
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 659
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 10, response size: 310
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_mlsag_done
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 269
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 10, response size: 115
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_sign_input
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 1591
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 1825, response size: 776
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: tsx_sign_input
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 1591
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 1821, response size: 776
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Action: final
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG Starting new HTTP connection (1): 127.0.0.1
2018-05-15 21:42:20 phx.local urllib3.connectionpool[20798] DEBUG http://127.0.0.1:46123 "POST /api/v1.0/tx_sign HTTP/1.1" 200 485
2018-05-15 21:42:20 phx.local __main__[20798] DEBUG Req size: 10, response size: 223
Signed transaction file: signed_monero_tx
Key images: ['a248206cea806a7d60ea936cdc35efdf44a189b1026c4e658f42216aec155383', '72565486bd4f78901168394b74881c66e19400456f8042c1bce592dc23985ef4', '3a839b03c02704801e72a5335f81deda067afa8f396059ee3fdc22c8b3205898', '192f831eb95784dd92bc11c5eb4e6dcda04313debd707318268ddcd9770f4582', '0100000000000000000000000000000000000000000000000000000000000000', 'b6008ee626e30fa28798e71c3a09095d226e3cc2cc78eb20aee7732104283826']
```

## Submit transfer

Use watch only hot wallet to submit signed transaction. This step performs also key image synchronisation so
hot wallet is able to construct new transactions, otherwise it could construct invalid transactions
without knowing which UTXOs have been spent which leads to double spending error.

Place `signed_monero_tx` file produced by the Agent to the running directory of the wallet.

```
[wallet 9sj6vz]: submit_transfer
Loaded 1 transactions, for 97.022799320000, fee 0.009759120000, sending 1.900000000000 to 9twQxUpHzXrQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB7ufnmk, 95.113040200000 change to 9yBfm6wd3beKaVBv3BU9SfJNXhwksKMByVhpazXFS6TKcqFksNUZHtpcsyaDheNq1RX2Xi3WQMhx82PKzrB6pTm5Ebu3Dgb, with min ring size 7, no payment ID. 6 key images to import. Is this okay? (Y/Yes/N/No): y
Transaction successfully submitted, transaction <ffbb3a5147b199debe482de2f7ba2d183a6417d45c1cfb5f1c182c25a7865fd4>
You can check its status by using the `show_transfers` command.
```

# Seed utility

There is a small utility provided for converting mnemonics to Monero wallets.

It generates Monero private/public keys, addresses and sub-addresses from the input which can be:

- BIP44 mnemonics as used with Trezor
- BIP44 master seed derived from mnemonics
- Monero electrum mnemonics
- Monero master seed

Example:

```
$> python -m monero_poc.seed --electrum-mnemonics --subs --testnet obedient coexist syringe lamb tacit hover hold subtly industrial puppy superior object push lakes geek welders oust colony rapid ointment thorn spiders mechanic nobody ointment
Seed Monero:      283d8bab1aeaee8f8b5aed982fc894c67d3e03db9006e488321c053f5183310d
Seed Monero wrds: obedient coexist syringe lamb tacit hover hold subtly industrial puppy superior object push lakes geek welders oust colony rapid ointment thorn spiders mechanic nobody ointment

Private spend key: 283d8bab1aeaee8f8b5aed982fc894c67d3e03db9006e488321c053f5183310d
Private view key:  9e7aba8ae9ee134e5d5464d9145a4db26793d7411af7d06f20e755cb2a5ad50f

Public spend key:  2ec1035565f1918b8c4740d4e5431ddcf50a670ab51984c78d9c0afff5a46a0d
Public view key:   f51121f7d68317c2b1b2d0f7ded72e106908cfbc5c0333f07dda1a716385c659

Mainnet Address:   43PsUEA2iAkQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB9o6iVc
Testnet Address:   9twQxUpHzXrQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB7ufnmk
Stagenet Address:  53buZ54zMmrQLnph1ZNFQgdxZZyGhKRLfaNv7EEgWc1f3LQPSZR7BP4ZZn4oH7kAbX3kCd4oDYHg6hE541rQTKtHB7w5L7m
Testnet Sub addresses:
 0, 1: BZZeyHTQYZ9W9KX2M69WWxWat1Z6JQYsi4LjnZxuVTmCbsNxrUyLFbXiZHRwXgBcaESRz8HtHxTDGSCtgxDdEFpQFrKqXoX
 0, 2: BhJN8SPSRxWMvawwAy82S2LiMbVMKr8Zefv9kZ3ELYHNQ6jrR18z2jeZxSWz8b25GMFqi8xwuDBYxWRuwNpVf3NKCZbTjkb
 0, 3: Bg8XwJYEseMSkQWBGxN7RbTP79s1kbJYCHacSHD3GocQHxs4SayWmFDSDSv81UD3UkbGkG1UV8kqpfAoWbUq4MFs7S6HFyr
 0, 4: BbTY7znMxcS5SWCEbMFezuUg3U9dz6cfc5tRLyAGdSHuDPsMpL1PATmfm7r9CpgJoK7oqi4LJzefSKJ6UnLm1rk4K6jBhsc
 1, 0: BcACPfJgD79JPEHXGvZ2Wx1GpMBMDMkk16toWj6iLTikVz79X8oCNTM2BaETx7tEMGVRE7Mz4efT5jAfHB3RPvpe5jUhFLG
 1, 1: BaLGM1RiMrNCtSFt7GRokGCBMbTNbcbHtCVbLmWXysap1MEbRWhtrXv4fj6ni8wVGVe194ix7d7wp2tvJfDhXrRqQYsKpxt
 1, 2: BdGPABuMmjZU9Bwe7mxLq69m32u82PEApdiGajfzQ4UiD59KJs8bRRGWuoPrcPtxZGPnYkwbpMhT4KRa5QF4HcV6K5bpsQQ
 1, 3: BZHc5i9TidM3J3Yxffyju7VRJ1Dceh8GTPR1u6FmxqjaASLBbAWymBmPPMuqHLAwSJWcVtjwfnjhfesALb2Rgnr2698mqvT
 1, 4: BaNAM54d4NsYvdZZ4UbQQGDehMMg6ZvZzcDyfTcQC5WhSjnAjazDZwPip3E2e1MWo8HRJHjvbzgbxCHSjew76cQwHqWsbg9
 2, 0: BetigrX7uP1c3UKDdaicCu7QYtFG1zzvt7VBBPzaGBafZLqp21Rq1BAN8PjtpNJp8tNrqdC7jKnynXpg2fVvzdr9KneLJiK
 2, 1: BYjxukg8AXbR1ee3T2kRzQLUfCoSG4uJzGHMW5ZqtpNGiSvmNgKo16MWpAQYP3iDbVhio8p7WWyMQLLMdrXg25ji5Bf7C4c
 2, 2: Bd5iVVwrV6g8S3cLdYjegtSKikRCa13PbY6boSdhrtcC4A2SGXpvSauFSV5837R9vSUwEhiu2CVL85UcUhnM1usVMYkHdxE
 2, 3: BecHsbxHU79YUb2MLqeCsqChmSv5XFbJe2az3HZNG2EkAVLUautytJUBqhk17CbWzBPW3hAmSpLzxgdcnJC958xw3BNuH5D
 2, 4: BYvUqAfzZVmNXyuWgqbxs36yXjFMHpSofHDRm1JfRpUbcGahL4FLZtD5AwkM5jZhZt6188M9u2qkv7UugFhnvKaYUDxLUSg
 3, 0: Bc2WDeJR7skc3ds4ZoFboBDFp3AjL1FW4YpKjmzxx4McEnrgAC2hz9ZN7rtyBMWqWmCu68pCHrL9AbVFtoreDHGs5Xg7rPG
 3, 1: BakckdKXPA5LZ2ZMdRSvMCgNqtv4ARtZqYSBsMXoyWQKY48c1VyQDD8PhEXgYw4wuPQr9gX2q1Ar1b27Lgy1kBwL3H9czHz
 3, 2: BYp7PBihf9zLDEm13w3JJD8ANKo1Hc8WZQrA9irzjUQHVogW8MPdi4HCZzLZkke8sdg5kdP64vnag5fGyveK9wjWNuqRJdP
 3, 3: BctxVqtngEg37ximN16rAP5P9egKXmqAnj3TSCfEq1n9Tu3xN3uhgGXTAp7CvtAZrcXEk8Z8rsmhvS7dMTFb5tvh4L4XxbD
 3, 4: BdSBrrVpvRzZXn2DVwmqNQbT77DVcoDCmXeFTUQFwaXci9rxEAborJMc32CqRfAGqaFX2UmrjG8JL7QJUYwraShPNFPYvUm
 4, 0: Bd6j33Qf37YURkfAJ9PSUAWdATx3bbMj6FF2KTjzKPTN3GpjboGW7BtStrxaydyqQZ8dJNJ9KdJ9LXaMpapnpDjN1jHZ2kp
 4, 1: BaHDgRVHiy8MRXdryKaUit8aZzbKGKcxBN2VwSyahpsTYJsahAzD692evawPSuPt1UcmqY9EiWoKpZ2m4GoZoCaqHV7Moxt
 4, 2: Bcytpo6X87jGbC7xX8B3kpJMWiTaHtnuNBnzZgY6YLRiJQm17zyaTWhgfGamF3etPhJws4paxNA5mRaHdfpNDQ5bDTetwjG
 4, 3: Bcj8Qc2aXXED5f8uhEmRhAL54PmgnWaT7HEMEs5GsRU9Ccuw1FTkhaP1fE3U9Mm69CWjfgGWc9kko4R9RY64rmEe8VZFU4d
 4, 4: BaWCZzMwtXFTaCj4wSNDnni13zVszkiBbeP2v7KDG9mZUvQWoE7PtXV5ga4WRrvCrUJ1PjmFP1kFNTowckgndCQYVsmA5nH
```

# Testing with Trezor

Agent supports also communication with Trezor directly.
It works in the same way as described above. If the account file does not exist on the agent start it will
prompt Trezor for watch-only credentials.

Agent requires `python-trezor` which facilitates communication with the Trezor over Trezor protocol.

```
$> pip install .[trezor]
```

The following command for communication with the Trezor Emulator running on port 21324.

```bash
python -m monero_poc.agent --debug --account-file agent25.json --watch-wallet wallet25 \
    --monero-bin ~/workspace/monero/build/debug/bin/ \
    --rpc-addr 127.0.0.1:28081 \
    --testnet \
    --trezor --trezor-path udp:127.0.0.1:21324
```

Or to communicate directly with the Trezor device connected to the USB:

```bash
python -m monero_poc.agent --debug --account-file agent25.json --watch-wallet wallet25 \
    --monero-bin ~/workspace/monero/build/debug/bin/ \
    --rpc-addr 127.0.0.1:28081 \
    --testnet \
    --trezor --trezor-path bridge:web01
```

## Testing

For testing I recommend setting `PYOPT` variable to `0` in `SConstript.firmware` file which enables debug mode on
the Trezor (both emulator and hardware device).

With the debug mode you are allowed to initialize the device with seed you want so you can run tests with the device.

Also you should get an access to the serial console for the hardware device to see logging output:

```
# Minicom serial console:
$> minicom -b 115200 -D /dev/tty.usbmodem1413

# Screen also works, set 3000 lines limit
$> screen -h 3000 /dev/tty.usbmodem1413 115200

# My utility, simple scrolling, augmenting log output with time
$> python -m monero_poc.log_aux --serial /dev/tty.usbmodem1413

589618000 apps.monero.sign_tx DEBUG TsxSigner. Free: 70784 Allocated: 89728
589621000 apps.monero.sign_tx DEBUG TsxState: <TsxSignStateHolder object at 20017d60>
589645000 apps.monero.protocol.tsx_sign DEBUG sign()
589657000 apps.monero.protocol.tsx_sign DEBUG Mem Free: 69936 Allocated: 90576
589802000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace (10, False), ... F: 42336 A: 118176, S: 2744
589809000 apps.monero.protocol.tsx_sign DEBUG sign_sinp
590049000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace 1, ... F: 43152 A: 117360, S: 2504
590075000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace 2, ... F: 43088 A: 117424, S: 2504
590109000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace 3, ... F: 42272 A: 118240, S: 2504
590155000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace 4, ... F: 42048 A: 118464, S: 2504
590546000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace 5, ... F: 40672 A: 119840, S: 2504
590579000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace 6, ... F: 40336 A: 120176, S: 2504
590604000 apps.monero.protocol.tsx_sign_builder DEBUG Log trace None, ... F: 40336 A: 120176, S: 2504
590707000 trezor.wire DEBUG 0:0 write: <MoneroTransactionSignInputAck>
591031000 apps.monero.sign_tx DEBUG ############################ TSX. Free: 64096 Allocated: 96416 thr: 112440
```

## Testing in emulator

```
make build_unix
PYOPT=0 make emu
```

## Testing with the device

To upload a new firmware image you need to switch Trezor to the bootloader mode.
This is done by constantly moving finger across device display while connecting device to the USB (on device powerup).
In case of success the white screen appears, asking whether to connect to the host.

```
PATH=/absolute_path_to_toolchain/gcc-arm/gcc-arm-none-eabi-5_4-2016q3/bin/:$PATH PYOPT=1 make build_firmware
PATH=/absolute_path_to_toolchain/gcc-arm/gcc-arm-none-eabi-5_4-2016q3/bin/:$PATH PYOPT=1 make upload
```

## Running tests

There are tests implemented to test `trezor-core` monero implementation. To run these tests call

```
EC_BACKEND_FORCE=1 EC_BACKEND=1 python -m unittest trezor_monero_test/test_trezor.py
```

The environment variables will force monero agent to use py-trezor-crypto library which is fast and secure.
Tests read `TREZOR_PATH` environment variable which defaults to `udp:127.0.0.1:21324`.

Currently there are 16 different transaction scenarios implemented and one key image sync.


## Changes on trezor-common updates

Once trezor-common is updated, e.g., new message type is added the following steps are needed to do:


### trezor-core

```
# 1. Update vendor trezor-common submodule in trezor-core

# 2. Regenerate messages
cd tools
./build_protobuf
```

### python-trezor

```
# 1. Update vendor trezor-common submodule in python-trezor

# 2. Rebuild protobuf messages
python setup.py develop

# 3. Update python-trezor in monero-agent directory (or system wise)
pip install -U --no-cache ../python-trezor/
```


### agent

```
# 1. Update vendor trezor-common submodule in monero-agent

# 2. Rebuild protobuf messages
python setup.py develop
```
