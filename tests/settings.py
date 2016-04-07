# -*- coding: utf-8 -*-

"""Default options for the application.
"""

VERSION = '2.4' # current version
BASE_API_URL = 'https://api.digitalocean.com/v2'
DEFAULT_PROXY = None # proxy URL (e.g. 'localhost:8080')
DEFAULT_HOST = 'www.netflix.com' # default Netflix host
DEFAULT_TITLEID = 80001898 # '1000 Times good Night'
DEFAULT_PLAYBACK = 60 # number of seconds to play video
DEFAULT_TIMEOUT = 10 # default operation timeout in seconds
DEFAULT_TRIES = 4 # exponential back-off retry
DEFAULT_DELAY = 30 # exponential back-off delay
DEFAULT_BACKOFF = 2 # exponential back-off
DOCKER_IMAGE_SLUG = 'docker'
DEFAULT_FINGERPRINT = ['d1:b6:92:ea:cc:4c:fe:9c:c5:ef:27:ce:33:1f:ba:61']
DEFAULT_REGION_SLUG = 'nyc3'
DEFAULT_MEMORY_SIZE_SLUG = '512mb'
DEFAULT_VCPUS = 1
DEFAULT_DISK_SIZE = 20
DEFAULT_SLEEP = 5
DEFAULT_BRANCH = 'master'
DEFAULT_HE_TB_INDEX = 1
