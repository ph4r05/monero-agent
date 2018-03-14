#see the aggregate schnorr pdf contained in this repository for an explanation. 
from . import mininero
from . import PaperWallet

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def GenSchnorr(hash_prefix, pub, sec, k): 
    #modified from original algorithm to match Monero better
    #see the ag schnorr pdf for original alg.
    #Note in Monero, hash prefix is always 32 bytes..
    #hash_prefix = binascii.hexlify(prefix) 
    #k = PaperWallet.skGen() #comment for testing
    comm = mininero.scalarmultBase(k)
    print("comm", "hash_prefix", comm, hash_prefix)
    if mininero.scalarmultBase(sec) != pub:
        print("error in genSchnorr")
        return -1
    if mininero.sc_check(sec) == False:
        print("fail in geSchnorr")
        return -1
    c = mininero.sc_reduce_key(mininero.cn_fast_hash(hash_prefix + pub + comm))
    r = mininero.sc_sub_keys(k, mininero.sc_mul_keys(c, sec))
    #uncomment to test malleability
    c = mininero.sc_reduce_key(mininero.cn_fast_hash(hash_prefix + pub + comm))
    r = mininero.sc_unreduce_key(mininero.sc_sub_keys(k, mininero.sc_mul_keys(c, sec)))

    return r, c

def VerSchnorr(hash_prefix, pub, r, c):
    #hash_prefix = binascii.hexlify(prefix)
    check1 = mininero.toPoint(pub) 
    comm = mininero.addKeys(mininero.scalarmultKey(pub,c), mininero.scalarmultBase(r))
    c2 = mininero.cn_fast_hash(hash_prefix + pub + comm)
    print(mininero.sc_sub_keys(c, c2) == "0000000000000000000000000000000000000000000000000000000000000000")
    return (mininero.sc_sub_keys(c, c2) == "0000000000000000000000000000000000000000000000000000000000000000")

def GenSchnorrNonLinkable(x, P1, P2, index):
    if index == 0:
        a = PaperWallet.skGen()
        L1 = mininero.scalarmultBase(a)
        s2 = PaperWallet.skGen()
        c2 = mininero.cn_fast_hash(L1)
        L2 = mininero.addKeys(mininero.scalarmultBase(s2), mininero.scalarmultKey(P2, c2))
        c1 = mininero.cn_fast_hash(L2)
        s1 = mininero.sc_mulsub_keys(a,  x, c1)
    if index == 1:
        a = PaperWallet.skGen()
        L2 = mininero.scalarmultBase(a)
        s1 = PaperWallet.skGen()
        c1 = mininero.cn_fast_hash(L2)
        L1 = mininero.addKeys(mininero.scalarmultBase(s1), mininero.scalarmultKey(P1, c1))
        c2 = mininero.cn_fast_hash(L1)
        s2 = mininero.sc_mulsub_keys(a,  x, c2)
    return L1, s1, s2,

def VerSchnorrNonLinkable(P1, P2, L1, s1, s2):
    c2 = mininero.cn_fast_hash(L1)
    L2 = mininero.addKeys(mininero.scalarmultBase(s2), mininero.scalarmultKey(P2, c2))
    c1 = mininero.cn_fast_hash(L2)
    L1p = mininero.addKeys(mininero.scalarmultBase(s1), mininero.scalarmultKey(P1, c1))
    if L1 == L1p:
        print("Verified")
        return 0
    else:
        print("Didn't verify")
        print(L1,"!=",  L1p)
        return -1

    

def GenASNL(x, P1, P2, indices):
    #Aggregate Schnorr Non-Linkable
    #x, P1, P2, are key vectors here, but actually you 
    #indices specifices which column of the given row of the key vector you sign.
    #the key vector with the first or second key
    n = len(x)
    print("Generating Aggregate Schnorr Non-linkable Ring Signature")
    L1 = [None] * n
    s1 = [None] * n
    s2 = [None] * n
    s = mininero.intToHex(0)
    for j in range(0, n):
        L1[j], s1[j], s2[j] = GenSchnorrNonLinkable(x[j], P1[j], P2[j], indices[j])
        s = mininero.sc_add_keys(s, s1[j])
    return L1, s2, s
        
def VerASNL(P1, P2, L1, s2, s):
    #Aggregate Schnorr Non-Linkable
    print("Verifying Aggregate Schnorr Non-linkable Ring Signature")
    n = len(P1)
    LHS = mininero.scalarmultBase(mininero.intToHex(0))
    RHS = mininero.scalarmultBase(s)
    for j in range(0, n):
        c2 = mininero.cn_fast_hash(L1[j])
        L2 = mininero.addKeys(mininero.scalarmultBase(s2[j]), mininero.scalarmultKey(P2[j], c2))
        LHS = mininero.addKeys(LHS, L1[j])
        c1 = mininero.cn_fast_hash(L2)
        RHS = mininero.addKeys(RHS, mininero.scalarmultKey(P1[j], c1))
    if LHS == RHS:
        print("Verified")
        return 0
    else:
        print("Didn't verify")
        print(LHS,"!=",  RHS)
        return -1
        
