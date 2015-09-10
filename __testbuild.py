#!/usr/bin/env python

import sys, urllib, urllib2

debug_proxy = None

urllib2.install_opener(
    urllib2.build_opener(
        urllib2.ProxyHandler(debug_proxy)
    )
)

secret = sys.argv[1]
base_url = 'https://api.digitalocean.com/v2'

request = urllib2.Request(base_url + '/regions')
request.add_header('Authorization', 'Bearer ' + secret)
response = urllib2.urlopen(request)
print response.read()
