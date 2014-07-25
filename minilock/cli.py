
from optparse import OptionParser
from getpass import getpass
from os.path import basename

from .minilockid import *
from .minilockfile import *

from nacl.utils import random
from base58 import b58encode

def get_id_private(options):
    if options.private:
        return id_private_from_key(options.private)
    email = options.email
    while email is None:
        email = raw_input('E-mail: ')
    password = getpass('Passphrase: ')
    return IDPrivateKey(password, email)


def main():
    parser = OptionParser()
    parser.add_option('-g', '--gen-id',
                      dest='genid',
                      action='store_true',
                      default=False,
                      help='Generate a miniLockid and then quit.')
    parser.add_option('--reveal-private-key',
                      dest='revealpk',
                      default=False,
                      action='store_true',
                      help='When used with -g, reveals private key '
                           '(dangerous!)')
    parser.add_option('-e', '--email',
                      dest='email',
                      default=None,
                      action='store',
                      type='str',
                      help='Specify e-mail. (usually required.)')
    parser.add_option('-p', '--private-key',
                      dest='private',
                      default=None,
                      action='store',
                      type='str',
                      help='Specify private key.')
    parser.add_option('-d', '--dest',
                      dest='dests',
                      action='append',
                      type='str',
                      help='Specify destination minilockids. Can be '
                           'used more than once.')
    parser.add_option('-i', '--encrypt',
                      dest='encrypt',
                      action='store',
                      type='str',
                      default=None,
                      help='Encrypt file.')
    parser.add_option('-o', '--decrypt',
                      dest='decrypt',
                      action='store',
                      type='str',
                      default=None,
                      help='Decrypt file.')
    (options, args) = parser.parse_args()

    if options.genid:
        pk = get_id_private(options)
        print("miniLockid: {}".format(pk.pub_base58()))
        if options.revealpk:
            print("Private Key: {}".format(pk.pri_base58()))
    elif options.encrypt:
        if options.dests is None:
            print('WARNING: No destination IDs specified. Encrypting to '
                  'self.')
            pids = [pk.to_public_key()]
        else:
            pids = map(PublicID, options.dests)
        with open(options.encrypt, 'rb') as f:
            d = f.read()
        fname = b58encode(random(8)) + '.minilock'
        pk = get_id_private(options)
        with open(fname, 'wb') as f:
            f.write(encrypt_file(d, basename(options.encrypt), pk, pids))
        print("Encrypted {} to {}.".format(basename(options.encrypt),
                                           fname))
    elif options.decrypt:
        with open(options.decrypt, 'rb') as f:
            d = f.read()
        if d[:16] != 'miniLockFileYes.':
            print "Not a miniLock file."
            return
        pk = get_id_private(options)
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

