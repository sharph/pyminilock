
from optparse import OptionParser
from getpass import getpass
from os.path import basename

from .minilockid import *
from .minilockfile import *

from nacl.utils import random
from base58 import b58encode

def main():
    parser = OptionParser()
    parser.add_option('-g', '--gen-id',
                      dest='genid',
                      action='store_true',
                      default=False,
                      help='Generate a miniLockid and then quit.')
    parser.add_option('-i', '--mlid',
                      dest='mlid',
                      default=None,
                      action='store',
                      type='str',
                      help='Specify the miniLockid of the current user.')
    parser.add_option('-d', '--dest',
                      dest='dests',
                      action='append',
                      type='str',
                      help='Specify destination minilockids. Can be '
                           'used more than once.')
    parser.add_option('-s', '--short',
                      dest='salt',
                      action='store_false',
                      default=True,
                      help='Generate miniLockid from password only. '
                           '(Insecure!)')
    parser.add_option('-e', '--encrypt',
                      dest='encrypt',
                      action='store',
                      type='str',
                      default=None,
                      help='Encrypt file.')
    parser.add_option('-x', '--decrypt',
                      dest='decrypt',
                      action='store',
                      type='str',
                      default=None,
                      help='Decrypt file.')
    (options, args) = parser.parse_args()

    if options.genid:
        password = getpass('Passphrase: ')
        b58 = IDPrivateKey(password, randomsalt=options.salt).\
              pub_base58()
        print("miniLockid: {}".format(b58))
    elif options.mlid is None and options.salt:
        print('You must set the short miniLock ID option or '
              'specify your full ID.')
    elif options.encrypt:
        password = getpass('Passphrase: ')
        pk = IDPrivateKey(password, options.mlid, randomsalt=False)
        if options.dests is None:
            print('WARNING: No destination IDs specified. Encrypting to '
                  'self.')
            pids = [pk.to_public_key()]
        else:
            pids = map(PublicID, options.dests)
        with open(options.encrypt, 'rb') as f:
            d = f.read()
        fname = b58encode(random(8)) + '.minilock'
        with open(fname, 'wb') as f:
            f.write(encrypt_file(d, basename(options.encrypt), pk, pids))
        print("Encrypted {} to {}.".format(basename(options.encrypt),
                                           fname))
    elif options.decrypt:
        password = getpass('Passphrase: ')
        pk = IDPrivateKey(password, options.mlid, randomsalt=False)
        with open(options.decrypt, 'rb') as f:
            d = f.read()
        if d[:16] != 'miniLockFileYes.':
            print "Not a miniLock file."
            return
        try:
            sender, fname, d = decrypt_file(d, pk)
        except DecryptionError:
            print "Decryption failed."
            return
        fname = basename(fname) # rudimentary prevention against attack
        with open(fname, 'wb') as f:
            f.write(d)
        print("From {}.".format(sender))
        print("Decrypted {} to {}.".format(basename(options.decrypt),
                                            fname))
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

