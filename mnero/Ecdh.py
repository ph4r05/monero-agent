#Elliptic Curve Diffie Helman with ed25519
#ecdhgen and ecdhretrieve translated into mininero from implementation by TacoTime
from . import mininero
from . import PaperWallet

def ecdhGen(P):
  ephembytes, ephempub = PaperWallet.skpkGen() 
  sspub = mininero.scalarmultKey(P, ephembytes) #(receiver pub) * (sender ecdh sk)
  ss1 = mininero.cn_fast_hash(sspub)
  ss2 = mininero.cn_fast_hash(ss1)
  return ephembytes, ephempub, ss1, ss2
  
def ecdhRetrieve(x, pk):
  sspub = mininero.scalarmultKey(pk, x)
  ss1 = mininero.cn_fast_hash(sspub)
  ss2 = mininero.cn_fast_hash(ss1)
  return ss1, ss2

