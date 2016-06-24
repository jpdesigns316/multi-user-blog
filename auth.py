# User Authentication library
# Most of the authentication and password creation information was taken
# out of the blog.py and moved to a separate file for added secruity. The
# secret is a long password utilizing the strongest methods. This refers
# to having at least 1 capital letter, 1 lowercase letter, 1 valid symbol,
# and 1 numeric digit.
#
# imports
import hashlib
import hmac
import random

from string import letters


# 64-bits
secret = 'Kj853y93k89xwzD#59G87588zE93374h6X4KrWY4Gq5447Hz482g2%54%73D43s2'


def make_salt(length=5):
    """
    Create a random string of characters.
    :length = The length of random characters. (Default 5)
    """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """
    Create a hash for the password based on the Sha256 security. If there is 
    no salt, then one will be created
    :name = the username that has entered the infomration
    :pw = The password which is to be hashed
    :salt = The random character string (Default is None)
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """
    Validation check to make sure the inputed password matches the hashed
    version fo the password
    :name = the username
    :password = the entered password
    """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def make_secure_val(val):
    """
    Used to create a cookie on the client-side
    :val = the value of the cookie
    """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """
    Validated the cookie on the client-side against what the server-side
    shows information should be
    :secure_val = the value of the cookie on the server-side
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
