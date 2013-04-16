#-----------------------------------------------------------------------------#
#                            PACKAGE AND MODULE IMPORTS                       #
#-----------------------------------------------------------------------------#

import re

#-----------------------------------------------------------------------------#

"""
Checks if the username is valid based on the following:
- between 3 to 20 characters long
- contains any combination of 'a-z', 'A-Z', '0-9', '_', '-'

Args: (i) username in string format

Returns: (i) True if it is a valid username, otherwise return False
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

#-----------------------------------------------------------------------------#

"""
Checks if the password is valid based on the following:
- between 3 to 20 characters long

Args: (i) password in string format

Returns: (i) True if it is a valid password, otherwise return False
"""
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

#-----------------------------------------------------------------------------#

"""
Checks if the email address is valid based on the following:
- [some characters] + '@' + [some characters] + '.' + [some characters]

Args: (i) email address in string format

Returns: (i) True if it is a valid email address, otherwise return False
"""
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#-----------------------------------------------------------------------------#
