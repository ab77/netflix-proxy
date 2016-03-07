#!/usr/bin/env python

import sys
from passlib.hash import pbkdf2_sha256
from passlib.utils import generate_password

try:
  plaintext = sys.argv[1]
except IndexError:
  plaintext = generate_password()

print plaintext, pbkdf2_sha256.encrypt(plaintext, rounds=200000, salt_size=16)
