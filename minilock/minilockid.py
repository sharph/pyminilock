

from scrypt import hash as scrypt

from base58 import b58encode, b58decode

from struct import pack, unpack

from nacl.public import PrivateKey, PublicKey
from nacl.hash import sha512
from nacl.encoding import RawEncoder
from nacl.utils import random

defaultsalt = 'miniLockScrypt..'

def id_private_from_key(key):
    k = IDPrivateKey()
    k.pri = PrivateKey(b58decode(key), encoder = RawEncoder)
    pub = PublicID()
    pub.salt = k.salt
    pub.key = k.pri.public_key.encode()
    k.pub = pub
    return k

class IDPrivateKey:
    
    def __init__(self, password = None, email = None):
        if email is None:
            self.salt = defaultsalt
        else:
            self.salt = email
        if password is not None:
            self.generate_key(password)

    def generate_key(self, password):
        self.pri = PrivateKey(scrypt(sha512(password,encoder = RawEncoder),
                                     self.salt,
                                     N = 1<<17,
                                     r = 8,
                                     p = 1,
                                     buflen = 32),
                              encoder = RawEncoder)
        pub = PublicID()
        pub.salt = self.salt
        pub.key = self.pri.public_key.encode()
        self.pub = pub

    def to_private_key(self):
        return self.pri

    def to_public_key(self):
        return self.pub

    def pri_base58(self):
        return b58encode(self.pri.encode(encoder = RawEncoder))

    def pub_base58(self):
        return self.pub.base58()


    
    
class PublicID:
    
    def __init__(self, idstr = None):
        self.key = None
        if idstr is not None:
            self.key = b58decode(idstr)
    
    def base58(self):
        return b58encode(self.key)

    def __str__(self):
        return self.base58()

    def to_public_key(self):
        return PublicKey(self.key, encoder = RawEncoder)

