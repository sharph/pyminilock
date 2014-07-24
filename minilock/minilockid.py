

from scrypt import hash as scrypt

from base58 import b58encode, b58decode

from struct import pack, unpack

from nacl.public import PrivateKey, PublicKey
from nacl.hash import sha512
from nacl.encoding import RawEncoder

defaultsalt = 'miniLockScrypt..'

class IDPrivateKey:
    
    def __init__(self, password = None, minilockid = None, customsalt = None):
        if minilockid is None:
            self.salt = defaultsalt
        else:
            self.salt = PublicID(minilockid).salt
        if customsalt is not None:
            salt.salt = customsalt
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

    def pub_base58(self):
        return self.pub.base58()


    
    
class PublicID:
    
    def __init__(self, idstr = None):
        self.salt = None
        self.key = None
        if idstr is not None:
            idstr = b58decode(idstr)
            if len(idstr) == 32:
                self.salt = defaultsalt
                self.key = idstr
            else:
                self.salt = idstr[-16:]
                self.key = idstr[:-16]
    
    def base58(self):
        if self.salt == defaultsalt:
            return b58encode(self.key)
        return b58encode(self.key + self.salt)

    def __str__(self):
        return self.base58()

    def to_public_key(self):
        return PublicKey(self.key, encoder = RawEncoder)

