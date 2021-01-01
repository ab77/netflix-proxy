# -*- coding: utf-8 -*-

"""Default options for the application.
"""

VERSION = '3.0' # current version
BASE_API_URL = 'https://api.digitalocean.com/v2'
DEFAULT_PROXY = None # proxy URL (e.g. 'localhost:8080')
DEFAULT_NFLX_HOST = 'www.netflix.com' # default Netflix host
DEFAULT_NFLX_TITLEID = 80001898 # '1000 Times Good Night'
DEFAULT_HULU_TITLEID = 249837 # South Park S01E01 "Cartman Gets an Anal Probe"
DEFAULT_PLAYBACK = 60 # number of seconds to play video
DEFAULT_TIMEOUT = 10 # default operation timeout in seconds
DEFAULT_TRIES = 4 # exponential back-off retry
DEFAULT_DELAY = 30 # exponential back-off delay
DEFAULT_BACKOFF = 2 # exponential back-off
DOCKER_IMAGE_SLUG = 'docker-20-04'
DEFAULT_FINGERPRINT = ['d1:b6:92:ea:cc:4c:fe:9c:c5:ef:27:ce:33:1f:ba:61']
DEFAULT_REGION_SLUG = 'nyc3'
DEFAULT_MEMORY_SIZE_SLUG = '1Gb'
DEFAULT_VCPUS = 1
DEFAULT_DISK_SIZE = 25
DEFAULT_SLEEP = 5
DEFAULT_BRANCH = 'master'
