

import json

from nacl.public import Box, PublicKey, PrivateKey
from nacl.secret import SecretBox
from nacl.encoding import RawEncoder, Base64Encoder
from nacl.exceptions import CryptoError
from nacl.utils import random

from base64 import b64decode, b64encode
from base58 import b58decode, b58encode

from . import minilockid

class DecryptionError(Exception):
    pass

class FileTypeError(Exception):
    pass

def _dec_from_dict(box, d):
    nonce, ctext = d['nonce'], d['data']
    nonce = b64decode(nonce)
    return box.decrypt(ctext, nonce, encoder=Base64Encoder)


def decrypt_file(data, idprivatekey):
    if data[:16] != 'miniLockFileYes.':
        raise FileTypeError
    metadata, data = data[16:].split('miniLockEndInfo.',1)
    metadata = json.loads(metadata)
    ephkey = PublicKey(metadata['ephemeral'], encoder=Base64Encoder)

    box = Box(idprivatekey.to_private_key(), ephkey)
    for nonce, ctext in metadata['fileInfo'].iteritems():
        nonce = b64decode(nonce)
        try:
            fileinfo = json.loads(box.decrypt(ctext, nonce,
                                              encoder=Base64Encoder))
            break
        except CryptoError:
            pass
    
    try:
        filenonce = b64decode(fileinfo['fileNonce'])
    except UnboundLocalError:
        raise DecryptionError
    
    sender = minilockid.PublicID(fileinfo['senderID'])
    senderkey = sender.to_public_key()
    box = Box(idprivatekey.to_private_key(), senderkey)

    filename = _dec_from_dict(box, fileinfo['fileName'])
    filename = filename.rstrip('\00')
    
    filekey = _dec_from_dict(box, fileinfo['fileKey'])
    
    box = SecretBox(filekey, encoder=RawEncoder)
    return sender, filename, box.decrypt(data, filenonce, encoder=RawEncoder)


def _enc_into_dict(box, data):
    nonce = random(Box.NONCE_SIZE)
    return {'data': box.encrypt(data,
                                nonce,
                                encoder=Base64Encoder).ciphertext,
            'nonce': b64encode(nonce)}


def encrypt_file(data, filename, idprivatekey, mlids):
    ephkey = PrivateKey.generate()

    senderid = idprivatekey.pub_base58()
    filenonce = random(SecretBox.NONCE_SIZE)
    filename = filename + ('\00' * (256-len(filename)) )
    filekey = random(SecretBox.KEY_SIZE)

    fileinfodict = {}
    for mlid in mlids:
        box = Box(idprivatekey.to_private_key(), mlid.to_public_key())
        fileinfo = {'fileNonce': b64encode(filenonce),
                    'senderID': senderid,
                    'fileKey': _enc_into_dict(box, filekey),
                    'fileName': _enc_into_dict(box, filename) }

        box = Box(ephkey, mlid.to_public_key())
        nonce = random(Box.NONCE_SIZE)
        fileinfodict[b64encode(nonce)] = \
            box.encrypt(json.dumps(fileinfo),
                        nonce,
                        encoder=Base64Encoder).ciphertext
    metadata = {'ephemeral': b64encode(ephkey.public_key.encode()),
                'fileInfo': fileinfodict}
    box = SecretBox(filekey, encoder=RawEncoder)
    return 'miniLockFileYes.' + json.dumps(metadata) + 'miniLockEndInfo.' + \
           box.encrypt(data, filenonce, encoder=RawEncoder).ciphertext

