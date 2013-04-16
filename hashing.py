#-----------------------------------------------------------------------------#
#                            PACKAGE AND MODULE IMPORTS                       #
#-----------------------------------------------------------------------------#

import random
import string
import hashlib

#-----------------------------------------------------------------------------#
"""
Makes a salt from combination of 5 random letters plus numbers.

Args: None

Returns: (i) salt in string format, 5 characters long
"""
def make_salt():
    char_set = string.letters + string.digits
    k = [random.choice(char_set) for x in range(5)]
    return ''.join(k)

#-----------------------------------------------------------------------------#
"""
Makes a password hash using input password and a random salt. Implemented 
using SHA-256

Args: (i)  password in string format;
      (ii) salt in string format (optional);

Returns: (i) string of password hash and the random salt seperated by a '|'
"""
def make_hash(k, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(k+salt).hexdigest()
    return '%s|%s' % (h, salt)

#-----------------------------------------------------------------------------#
"""
Checks if the password is valid by making a hash from it and by matching it 
against the combination of pre-existing hash and salt.

Args: (i)  password in string format;
      (ii) password hash and salt seperated by a '|' in string format;

Returns: (i) True if the hash of the password matches the pre-existing 
hash. otherwise return False
"""
def valid_hash(k, h):
    salt = h.split("|")[1]
    return h == make_hash(k, salt)
