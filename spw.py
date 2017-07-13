#!/usr/bin/env python
# -*- coding: utf-8 -*-

import string
import argparse
import struct
import os
from math import log, pow

spw_version = "1.0 - May 2017"


##############################################################################
class SPW_Password(object):
    """
    SPW_Password class is the main class generating the secure passwords.
    """

    __my_dictionary = None

    __Upper = set(string.ascii_uppercase)
    __Lower = set(string.ascii_lowercase)
    __Digits = set(string.digits)
    __Ambiguous = set("Il10O|")
    __Special = set("!@#$%&*-+=")
    __Extra = set("^?_:;.,~|")
    __Brackets = set("()[]{}<>")
    __Vowels = set("aeiouyAEIOUY")

    ##########################################################################
    def __init__(self, mode, length=23, password='', entropy=0):
        """ Class constructor. """

        self.mode = mode
        self.length = length
        self.password = password
        self.entropy = entropy

    ##########################################################################
    def _clear(self):
        """ Clears the current password and calculated entropy. """

        self.password = ''
        self.entropy = 0

    ##########################################################################
    @classmethod
    def _read_dictionary(self, dictionary, min_word_length, max_word_length):
        """ Reads words from dictionary for further use. """

        words = []
        try:
            with open(dictionary, 'r') as dictionary_file:
                for word in dictionary_file:
                    word = word.strip()
                    if word.endswith("'s"):
                        continue
                    if len(word) >= min_word_length and len(word) <= max_word_length:
                        words.append(word)
        except (IOError) as exc:
            error("{}".format(exc))
            exit(1)
        except Exception:
            raise

        return words

    ##########################################################################
    def _get_dictionary(self, dictionary, min_word_length, max_word_length):
        """ Calls main _read_dictionary function. """

        if not SPW_Password.__my_dictionary:
            SPW_Password.__my_dictionary = SPW_Password._read_dictionary(dictionary, min_word_length, max_word_length)
        return SPW_Password.__my_dictionary

    ##########################################################################
    def _get_baseline(self):
        """
        Generates the Baseline (character set). It is used to generate secure
        password from.
        """

        my_baseline = SPW_Password.__Upper.union(SPW_Password.__Lower).union(SPW_Password.__Digits)

        if 's' in self.mode:  # Add special characters
            my_baseline = my_baseline.union(SPW_Password.__Special)
        if 'e' in self.mode:  # Add extra characters
            my_baseline = my_baseline.union(SPW_Password.__Extra)
        if 'b' in self.mode:  # Add brackets characters
            my_baseline = my_baseline.union(SPW_Password.__Brackets)
        if 'u' in self.mode:  # Remove Upper case letters
            my_baseline = my_baseline.difference(SPW_Password.__Upper)
        if 'l' in self.mode:  # Remove Lower case letters
            my_baseline = my_baseline.difference(SPW_Password.__Lower)
        if 'd' in self.mode:  # Remove Digits
            my_baseline = my_baseline.difference(SPW_Password.__Digits)
        if 'a' in self.mode:  # Remove Ambiguous characters
            my_baseline = my_baseline.difference(SPW_Password.__Ambiguous)
        if 'v' in self.mode:  # Remove Vowels
            my_baseline = my_baseline.difference(SPW_Password.__Vowels)

        if len(my_baseline) == 0:
            error("Cannot create password from nothing...")
            exit(1)

        return my_baseline

    ##########################################################################
    def _calc_entropy(self, words=None):
        """
        Calculates password  entropy.
        The function uses two ways of calculation:
        a) Shannon's algorithm based on length of the password and the character set
           used to generate it, or
        b) the same algorithm but based on number of words in dictionary and number
           of chosen words from the dictionary.
        """

        result = 0

        if words and 'S' not in self.mode:
            assert isinstance(words, int), 'Argument of wrong type!'
            charset = words
        else:
            charset = 0
            password_set = set(self.password)
            if password_set.intersection(SPW_Password.__Upper):
                charset += len(SPW_Password.__Upper)
            if password_set.intersection(SPW_Password.__Lower):
                charset += len(SPW_Password.__Lower)
            if password_set.intersection(SPW_Password.__Digits):
                charset += len(SPW_Password.__Digits)
            if password_set.intersection(SPW_Password.__Special):
                charset += len(SPW_Password.__Special)
            if password_set.intersection(SPW_Password.__Extra):
                charset += len(SPW_Password.__Extra)
            if password_set.intersection(SPW_Password.__Brackets):
                charset += len(SPW_Password.__Brackets)

        try:
            if 'S' in self.mode:
                # Calculate Shannon entropy from length of password
                # instead of from number of randomised words
                result = log(pow(charset, len(self.password)), 2)
            else:
                result = log(pow(charset, self.length), 2)
        except:
            pass
        self.entropy = result

    ##########################################################################
    def get_entropy(self):
        """ Returns the calculated entropy """

        return self.entropy

    ##########################################################################
    def xkcd_gen(self, dictionary, separator='-', min_word_length=3, max_word_length=10):
        """
        Generates password phrases.
        self.length represents number of words to get from dictionary.
        The larger the dictionary is used, the higher entropy password will be generated.
        """

        if not min_word_length:
            min_word_length = 3
        if not max_word_length:
            max_word_length = 10

        words = self._get_dictionary(dictionary, min_word_length, max_word_length)
        self.password = separator.join([rnd.get_rand_char(words) for _ in range(self.length)])
        self._calc_entropy(len(words))

    ##########################################################################
    def readable_gen(self, dictionary, min_word_length, max_word_length):
        """
        Generates pseudo-readable passwords.
        The dictionary is used for the process. The function creates unique, random (2-5 characters
        long) atoms out of words from a dictionary. It puts randomly numbers and/or special characters
        between the atoms as requested.
        """

        if not min_word_length:
            min_word_length = 5
        if not max_word_length:
            max_word_length = 30

        words = self._get_dictionary(dictionary, min_word_length, max_word_length)

        passlength = self.length
        for _ in range(passlength):
            last_word = rnd.get_rand_char(words)[:rnd.get_int(2, 5)]

            # Capitalise an atom's first letter 50% at a time
            if 'u' not in self.mode:
                weight = rnd.get_int(1, 100)
                if weight <= 50:
                    last_word = last_word[0].upper() + last_word[1:]

            if last_word in self.password:
                passlength += 1
            else:
                self.password += last_word

                # Insert a digit between atoms 50% at a time is required
                if 'd' not in self.mode:
                    weight = rnd.get_int(1, 100)
                    if weight <= 50:
                        self.password += str(rnd.get_int(0, 9))
                # Insert a special character between atoms 50% at a time is required
                if 's' in self.mode:
                    weight = rnd.get_int(1, 100)
                    if weight <= 50:
                        self.password += str(rnd.get_rand_char(''.join(str(char) for char in SPW_Password.__Special)))
                # Insert an Extra character between atoms 50% at a time is required
                if 'e' in self.mode:
                    weight = rnd.get_int(1, 100)
                    if weight <= 50:
                        self.password += str(rnd.get_rand_char(''.join(str(char) for char in SPW_Password.__Extra)))
                # Insert a Bracket between atoms 50% at a time is required
                if 'b' in self.mode:
                    weight = rnd.get_int(1, 100)
                    if weight <= 50:
                        self.password += str(rnd.get_rand_char(''.join(str(char) for char in SPW_Password.__Brackets)))

        self.password = self.password[:self.length]

        # Make password lowercase if required
        if 'u' in self.mode:
            self.password = self.password.lower()
        # Make password uppercase if required
        if 'l' in self.mode:
            self.password = self.password.upper()

        self._calc_entropy()

    ##########################################################################
    def secure_pwgen(self):
        """
        Generates secure password out of randomised baseline (characters set).
        """

        Baseline = self._get_baseline()
        Baseline = ''.join(str(char) for char in Baseline)

        # Randomize the charset
        Baseline = ''.join(rnd.shuffle(Baseline))

        # Generate the password from randomized charset
        self.password = ''.join(rnd.get_rand_char(Baseline) for _ in range(self.length))

        self._calc_entropy()

    ##########################################################################
    def hash_pwgen(self, algorithm,  my_file, salt):
        """
        Generates password out of specified file and salt.
        """

        import hashlib

        BLOCKSIZE = 65536

        if algorithm == "sha1":
            hasher = hashlib.sha1(salt.encode('utf-8'))
        elif algorithm == "sha256":
            hasher = hashlib.sha256(salt.encode('utf-8'))

        try:
            with open(my_file, 'rb') as afile:
                buf = afile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile.read(BLOCKSIZE)
        except Exception as exc:
            error("{}.".format(exc))
            exit(1)

        self.mode.append('S')  # Force Shannon entropy for SHA* based passwords
        self.password = hasher.hexdigest()
        self._calc_entropy()


##############################################################################
class SPW_Random(object):
    """
    SPW_Random class is the main randomisation class.
    The elastic character of the class allows to use any Random Number Generators
    (including hardware generators) as a source of entropy.
    By default /dev/urandom is used, however the class has been tested with
    TrueRNG (http://ubld.it/products/truerng-hardware-random-number-generator) and
    OneRNG (http://onerng.info/) with a great success.
    """

    ##########################################################################
    def __init__(self, source='/dev/urandom'):
        """ Class constructor. """

        try:
            self._random_source = open(source, 'rb')
        except (IOError) as exc:
            warning("{}. Defaults back to /dev/urandom.".format(str(exc)))
            self._random_source = open('/dev/urandom', 'rb')
        except Exception:
            raise

    ##########################################################################
    def __del__(self):
        """ Class destructor. """

        try:
            self._random_source.close()
        except Exception:
            pass

    ##########################################################################
    def _random_bytes(self, length):
        """ Reads length bytes from the device. """

        return self._random_source.read(length)

    ##########################################################################
    def _unpack_uint32(self, bytes_buffer):
        """ Decode Bytes into integer. """

        tup = struct.unpack("I", bytes_buffer)
        return tup[0]

    ##########################################################################
    def get_int(self, low, high):
        """
        Return a random integer in the range [low, high], including both endpoints.
        """

        UINT32_MAX = 0xffffffff
        n = (high - low) + 1
        assert n >= 1
        scale_factor = n / float(UINT32_MAX + 1)
        random_uint32 = self._unpack_uint32(self._random_bytes(4))
        result = int(scale_factor * random_uint32) + low
        return result

    ##########################################################################
    def get_rand_char(self, spw_input):
        """ Returns a random character from string spw_input. """

        return spw_input[self.get_int(0, len(spw_input)-1)]

    ##########################################################################
    def shuffle(self, spw_input):
        """ Shuffles any given string """

        in_list = list(spw_input)
        out_list = []
        for _ in range(len(in_list)):
            element = self.get_rand_char(in_list)
            in_list.remove(element)
            out_list.append(element)

        return ''.join(out_list)


##############################################################################
class bcolors:
    """ Class declares the terminal colours. """

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


##############################################################################
def error(err):
    """ Display Errors """

    return error_handler('E', err)


##############################################################################
def warning(err):
    """ Display Warnings """

    return error_handler('W', err)


##############################################################################
def error_handler(etype, err):
    """ An Error and Warning handler """

    if 'E' in etype.upper():
        print(bcolors.FAIL, bcolors.BOLD, "ERROR: {}".format(err), bcolors.ENDC)
    if 'W' in etype.upper():
        print(bcolors.WARNING, bcolors.BOLD, "WARNING: {}".format(err), bcolors.ENDC)


##############################################################################
def get_boolean(mystr):
    """ Convert string to boolean if possible, otherwise returns the string. """

    if mystr.lower() in ['true', 'yes', '1']:
        return True
    elif mystr.lower() in ['false', 'no', '0']:
        return False
    else:
        return mystr


##############################################################################
def get_pair(line):
    """ Decouple of the tuple """

    key, sep, value = line.strip().partition("=")
    return key.strip(), get_boolean(value.strip())


##############################################################################
def read_defaults():
   #goal_dir = os.path.join(os.getcwd(), 'dict/spw_en')

    dict_path = '/private/etc/spw_en'
    for root, dirs, files in os.walk(dict_path):
        for name in files:
            if name == dict_path:
                os.path.abspath(os.path.join(root, name))


                  #from os.path import expanduser

    defaults = {
                'num_pw': 20,
                'pw_length': 30,
                'noupper': False,
                'nolower': False,
                'nodigits': False,
                'noambiguous': False,
                'special': False,
                'extra': False,
                'brackets': False,
                'single': False,
                'source': '/dev/urandom',
                'dictionary': dict_path,
               }

    # config_files = ['/etc/spw.conf', "{}/.spw.conf".format(expanduser('~'))]
    #
    # for config in config_files:
    #     try:
    #         with open(config) as my_defaults:
    #             for line in my_defaults:
    #                 line = line.strip()
    #                 if line and "#" not in line:
    #                     key, value = get_pair(line)
    #                     defaults[key] = value
    #     except:
    #         pass

    return defaults


##############################################################################
def read_arguments():
    """ Arguments parser. """

    defaults = read_defaults()

    parser = argparse.ArgumentParser(description='''
The SPW generates secure passwords using multiple algorithms.
It allows for the use of hardware Random Number Generators
aiming to provide the highest possible level of security and entropy
of one\'s password.

The script has been tested with:
  - TrueRNG (http://ubld.it/products/truerng-hardware-random-number-generator)
  - OneRNG (http://onerng.info).''', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-u", "--no-upper", dest="noupper", default=defaults['noupper'], help="exclude uppercase characters", action="store_true")
    parser.add_argument("-l", "--no-lower", dest="nolower", default=defaults['nolower'], help="exclude lowercase characters", action="store_true")
    parser.add_argument("-d", "--no-digits", dest="nodigits", default=defaults['nodigits'], help="exclude digits", action="store_true")
    parser.add_argument("-a", "--no-ambiguous", dest="noambiguous", default=defaults['noambiguous'], help="exclude ambiguous characters", action="store_true")
    parser.add_argument("-s", "--special", dest="special", default=defaults['special'], help="include special characters", action="store_true")
    parser.add_argument("-e", "--extra", dest="extra", default=defaults['extra'], help="include extra characters", action="store_true")
    parser.add_argument("-b", "--brackets", dest="brackets", default=defaults['brackets'], help="include brackets", action="store_true")
    parser.add_argument("pw_length",  nargs='?', default=defaults['pw_length'], action="store", help="password length")
    parser.add_argument("num_pw", nargs='?', default=defaults['num_pw'],  action="store", help="how many passwords to generate")

    exclusive1 = parser.add_mutually_exclusive_group()
    exclusive1.add_argument("-r", "--readable", help="readable password. (Less secure.)", action="store_true")
    exclusive1.add_argument("-x", "--xkcd", help="password phrases a'la XKCD (https://xkcd.com/936).", action="store_true")
    exclusive1.add_argument("--sha1", help="SHA-1 passwords of a given file + salt. (SHA1: /dir/file.ext[#salt])", action="store")
    exclusive1.add_argument("--sha256", help="SHA256 passwords of a given file + salt. (SHA256: /dir/file.ext[#salt])", action="store")

    xkcd = parser.add_argument_group("XKCD pass phrases related options")
    xkcd.add_argument("-m", "--min", dest="min_word_length", type=int, help="minimum word length for password phrase.", action="store")
    xkcd.add_argument("-M", "--max", dest="max_word_length", type=int, help="maximum word length for password phrase.", action="store")
    xkcd.add_argument("--separator", type=str, default="-", help="separator between words for password phrase.", action="store")
    xkcd.add_argument("-S", "--shannon", dest="shannon", default=False, help="calculate shannon entropy for XKCD password phrases.", action="store_true")

    adv = parser.add_argument_group("Advanced options")
    adv.add_argument("--source", default=defaults['source'],
                     dest="source",
                     help="rng device. (Default: " + defaults['source'] + ").",
                     metavar="RNGDEV")
    adv.add_argument("--dictionary", dest="dictionary",
                     default=defaults['dictionary'],
                     help="dictionary to be used. (Default: " + defaults['dictionary'] + ").",
                     metavar="DICT")

    adv.add_argument("-E", "--entropy", dest="entropy", default=False, help="calculate entropy.", action="store_true")
    adv.add_argument("-O", "--overwrite", dest="overwrite", default=False, help="overwrite any limits.", action="store_true")
    adv.add_argument("-1", "--single", dest="single", default=defaults['single'], help="print passwords in single column.", action="store_true")
    adv.add_argument("-v", "--version", dest="version", default=False, help="show version.", action="store_true")

    args = vars(parser.parse_args())

    if int(args['pw_length']) <= 0:
        parser.error('Cannot create a zero length password.')
    if int(args['num_pw']) <= 0:
        parser.error('Zero passwors? Why bother to call spw in the first place?')
    if args['version']:
        parser.exit(status=0, message='spw - version: {}\n'.format(spw_version))

    return parser.parse_args()


##############################################################################
if __name__ == '__main__':
    mode = []
    passwords = []
    counter = 0

    args = read_arguments()
    length = int(args.pw_length)

    if args.noupper:
        mode.append('u')
    if args.nolower:
        mode.append('l')
    if args.nodigits:
        mode.append('d')
    if args.noambiguous:
        mode.append('a')
    if args.special:
        mode.append('s')
    if args.extra:
        mode.append('e')
    if args.brackets:
        mode.append('b')
    if args.xkcd:
        if length > 10 and not args.overwrite:
            length = 10
        args.single = True
    if args.shannon:
        mode.append('S')

    if args.sha1 or args.sha256:
        try:
            if args.sha1:
                afile, asalt = args.sha1.split("#")
            elif args.sha256:
                afile, asalt = args.sha256.split("#")
        except (ValueError):
            warning('No salt specified. The passwords are not secure.')
            if args.sha1:
                afile = args.sha1
            elif args.sha256:
                afile = args.sha256
            asalt = ''
        except Exception:
            raise

    rnd = SPW_Random(args.source)

    for _ in range(int(args.num_pw)):
        # Let's generate some passwords.

        mypasswd = SPW_Password(mode, length)

        if args.readable:
            mypasswd.readable_gen(args.dictionary, args.min_word_length, args.max_word_length)
        elif args.xkcd:
            mypasswd.xkcd_gen(args.dictionary, args.separator, args.min_word_length, args.max_word_length)
        elif args.sha1:
            mypasswd.hash_pwgen('sha1', afile, asalt)
            asalt = mypasswd.password
        elif args.sha256:
            mypasswd.hash_pwgen('sha256', afile, asalt)
            asalt = mypasswd.password
        else:
            mypasswd.secure_pwgen()

        passwords.append(mypasswd)

        if not os.isatty(1):
            # Generate a  single password if the script has been called
            # with no TTY output.
            break

    for ind in range(len(passwords)):
        # Let's print out our passwords.

        if not args.single and ind % 2:
            continue

        if args.single or (ind == len(passwords)-1):
            if args.entropy or args.shannon:
                if args.sha1 or args.sha256:
                    print('{:2} --> {}  ({:.4f} bits)'.format(
                          ind+1,
                          passwords[ind].password,
                          passwords[ind].get_entropy()))
                else:
                    print('{}  ({:.4f} bits)'.format(
                          passwords[ind].password,
                          passwords[ind].get_entropy()))
            else:
                if args.sha1 or args.sha256:
                    print('{:2} --> {}'.format(ind+1, passwords[ind].password))
                else:
                    print('{}'.format(passwords[ind].password))
        else:
            if args.entropy or args.shannon:
                if args.sha1 or args.sha256:
                    print('{:2} --> {}  ({:.4f} bits)    {}  ({:.4f} bits)'.format(
                          ind+1,
                          passwords[ind].password,
                          passwords[ind].get_entropy(),
                          passwords[ind+1].password,
                          passwords[ind+1].get_entropy()))
                else:
                    print('{}  ({:.4f} bits)    {}  ({:.4f} bits)'.format(
                          passwords[ind].password,
                          passwords[ind].get_entropy(),
                          passwords[ind+1].password,
                          passwords[ind+1].get_entropy()))
            else:
                if args.sha1 or args.sha256:
                    print('{:2} --> {}   {:2} --> {}'.format(
                          ind+1,
                          passwords[ind].password,
                          ind+2,
                          passwords[ind+1].password))
                else:
                    print('{}   {}'.format(
                          passwords[ind].password,
                          passwords[ind+1].password))
