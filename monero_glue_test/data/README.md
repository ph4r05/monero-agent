
New trezor test vectors:

tsx_t_uns_01  - 1utxo to simple address
tsx_t_uns_02  - 1utxo to sub address
tsx_t_uns_03  - 1utxo to 2 normal addresses
tsx_t_uns_04  - 1utxo to 1 sub, 1 normal addresses

tsx_t_uns_05  - 2utxo to 3 normal addresses
tsx_t_uns_06  - 2utxo to 1 normal address
tsx_t_uns_07  - 2utxo to 1 sub address
tsx_t_uns_08  - 4utxo to 1 sub, 2 normal addresses
tsx_t_uns_09  - 11utxo to 1 sub, 2 normal addresses
tsx_t_uns_10  - 17utxo to 1 sub, 2 normal addresses

tsx_t_uns_11  - 21utxo to 1 normal address

tsx_t_uns_12  - 3 utxo to 1 normal address + payment id
tsx_t_uns_13  - 1 utxo to 1 sub address + payment id
tsx_t_uns_14  - 1 utxo to 1 normal address + payment id
tsx_t_uns_15  - 16 utxo to 1 normal address + payment id
tsx_t_uns_16  - 2 utxo to 1 sub address + plain payment id
tsx_t_uns_17  - 1 utxo to 5 normal
tsx_t_uns_18  - 4utxo to 1 sub, 2 normal addresses + plain payment id


transform test
tsx_t_uns_08  - 4utxo to 1 sub, 2 normal addresses
tsx_t_uns_12  - 3 utxo to 1 normal address + payment id


Generated description:

Inp: monero_glue_test/data/tsx_t_uns_01.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.990258, fee:   0.009742, change:   8.990258, out_clean:   1.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_02.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.990258, fee:   0.009742, change:   8.990258, out_clean:   1.000000
  Out: num_std:  0, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_03.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  3, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.986083, fee:   0.013917, change:   7.486083, out_clean:   2.500000
  Out: num_std:  2, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_04.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  3, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.986083, fee:   0.013917, change:   7.086083, out_clean:   2.900000
  Out: num_std:  1, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, AdditionalTxKeys: 3

Inp: monero_glue_test/data/tsx_t_uns_05.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  4, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.981908, fee:   0.018092, change:   5.781908, out_clean:   4.200000
  Out: num_std:  2, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_06.txt, #txs: 1
  tx: 0, #inp:  2, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  20.000000, xmr_out:  19.990258, fee:   0.009742, change:   6.990258, out_clean:  13.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_07.txt, #txs: 1
  tx: 0, #inp:  2, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  20.000000, xmr_out:  19.990258, fee:   0.009742, change:   5.990258, out_clean:  14.000000
  Out: num_std:  0, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_08.txt, #txs: 1
  tx: 0, #inp:  4, #inp_add:  0, #out:  4, acc: 0, subs: [0], xmr_in:  40.000000, xmr_out:  39.981212, fee:   0.018788, change:   2.181212, out_clean:  37.800000
  Out: num_std:  1, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, AdditionalTxKeys: 4

Inp: monero_glue_test/data/tsx_t_uns_08_sub.txt, #txs: 1
  tx: 0, #inp:  4, #inp_add:  0, #out:  4, acc: 2, subs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20], xmr_in:  40.000000, xmr_out:  39.981212, fee:   0.018788, change:   2.181212, out_clean:  37.800000
  Out: num_std:  1, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {2}, subs: 3
  Extras: TxKey, AdditionalTxKeys: 4

Inp: monero_glue_test/data/tsx_t_uns_08_sub_add.txt, #txs: 1
  tx: 0, #inp:  4, #inp_add:  4, #out:  4, acc: 1, subs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20], xmr_in:  40.000000, xmr_out:  39.981212, fee:   0.018788, change:   2.181212, out_clean:  37.800000
  Out: num_std:  1, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {1}, subs: 4
  Extras: TxKey, AdditionalTxKeys: 4

Inp: monero_glue_test/data/tsx_t_uns_09.txt, #txs: 1
  tx: 0, #inp: 11, #inp_add:  0, #out:  4, acc: 0, subs: [0], xmr_in: 110.000000, xmr_out: 109.978429, fee:   0.021571, change:   6.178429, out_clean: 103.800000
  Out: num_std:  1, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, AdditionalTxKeys: 4

Inp: monero_glue_test/data/tsx_t_uns_10.txt, #txs: 1
  tx: 0, #inp: 17, #inp_add:  0, #out:  4, acc: 0, subs: [0], xmr_in: 170.000000, xmr_out: 169.975645, fee:   0.024355, change:   6.175645, out_clean: 163.800000
  Out: num_std:  1, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, AdditionalTxKeys: 4

Inp: monero_glue_test/data/tsx_t_uns_11.txt, #txs: 1
  tx: 0, #inp: 21, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in: 210.000000, xmr_out: 209.983300, fee:   0.016700, change:   9.983300, out_clean: 200.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey

Inp: monero_glue_test/data/tsx_t_uns_12.txt, #txs: 1
  tx: 0, #inp:  3, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  30.000000, xmr_out:  29.989562, fee:   0.010438, change:   0.989562, out_clean:  29.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, Nonce: 01deadc0dedeadc0de

Inp: monero_glue_test/data/tsx_t_uns_12_sub.txt, #txs: 1
  tx: 0, #inp:  3, #inp_add:  0, #out:  2, acc: 2, subs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20], xmr_in:  30.000000, xmr_out:  29.989562, fee:   0.010438, change:   0.989562, out_clean:  29.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {2}, subs: 3
  Extras: TxKey, Nonce: 01deadc0dedeadc0de

Inp: monero_glue_test/data/tsx_t_uns_12_sub_add.txt, #txs: 1
  tx: 0, #inp:  3, #inp_add:  3, #out:  2, acc: 1, subs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20], xmr_in:  30.000000, xmr_out:  29.989562, fee:   0.010438, change:   0.989562, out_clean:  29.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {1}, subs: 3
  Extras: TxKey, Nonce: 01deadc0dedeadc0de

Inp: monero_glue_test/data/tsx_t_uns_13.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.990258, fee:   0.009742, change:   6.990258, out_clean:   3.000000
  Out: num_std:  0, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, Nonce: 01deadc0dedeadc0de

Inp: monero_glue_test/data/tsx_t_uns_14.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.990258, fee:   0.009742, change:   6.990258, out_clean:   3.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, Nonce: 01deadc0dedeadc0de

Inp: monero_glue_test/data/tsx_t_uns_15.txt, #txs: 1
  tx: 0, #inp: 16, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in: 160.000000, xmr_out: 159.984691, fee:   0.015309, change:   9.984691, out_clean: 150.000000
  Out: num_std:  1, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey, Nonce: 01deadc0dedeadc0de

Inp: monero_glue_test/data/tsx_t_uns_16.txt, #txs: 1
  tx: 0, #inp:  2, #inp_add:  0, #out:  2, acc: 0, subs: [0], xmr_in:  20.000000, xmr_out:  19.990258, fee:   0.009742, change:  18.990258, out_clean:   1.000000
  Out: num_std:  0, num_sub:  1, single_dest_sub: 1
  Ins: accounts: {0}, subs: 0
  Extras: Nonce: 00e8ce72659fbde7cc7c44871ca7784bba24b57323e66f7384ab06f2b8eea40649, TxKey

Inp: monero_glue_test/data/tsx_t_uns_17.txt, #txs: 1
  tx: 0, #inp:  1, #inp_add:  0, #out:  5, acc: 0, subs: [0], xmr_in:  10.000000, xmr_out:   9.981908, fee:   0.018092, change:   5.781908, out_clean:   4.200000
  Out: num_std:  2, num_sub:  0, single_dest_sub: 0
  Ins: accounts: {0}, subs: 0
  Extras: TxKey
