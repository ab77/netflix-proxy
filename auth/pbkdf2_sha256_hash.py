#!/usr/bin/env python

import sys
from passlib.hash import pbkdf2_sha256

print(pbkdf2_sha256.encrypt(sys.argv[1], rounds=200000, salt_size=16))
