import hashlib
import hmac

from Crypto.Protocol.KDF import PBKDF2


def mnemonics_to_seed(seed, passphrase=b""):
    salt = b"mnemonic" + passphrase

    def prf(p, s):
        hx = hmac.new(p, msg=s, digestmod=hashlib.sha512)
        return hx.digest()

    res = PBKDF2(password=seed, salt=salt, dkLen=64, prf=prf, count=2048)
    return res
