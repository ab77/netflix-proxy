# -*- coding: utf-8 -*-

"""Default options for the application.
"""

VERSION = '0.1' # current version
DEFAULT_PROXY = None # proxy (e.g. 'localhost:8080')
DEFAULT_HOST = 'www.netflix.com' # default Netflix host
DEFAULT_TITLEID = 80001898 # '1000 Times good Night'
DEFAULT_PLAYBACK = 60 # number of seconds to play video
DEFAULT_TIMEOUT = 10 # default operation timeout in seconds
DEFAULT_TRIES = 3 # exponential back-off retry
DEFAULT_DELAY = 10 # exponential back-off delay
DEFAULT_BACKOFF = 2 # exponential back-off
