#!/usr/bin/env python

import sys
from passlib.hash import pbkdf2_sha256
from passlib.hash import plaintext as plaintext
from passlib import pwd

try:
  plaintext = sys.argv[1]
except IndexError:
  plaintext = pwd.genword()

print(plaintext, pbkdf2_sha256.hash(plaintext, rounds=200000, salt_size=16))
