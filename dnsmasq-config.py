#!/usr/bin/python

# Parse domains from BIND config (data/zones.override) and output dnsmasq
# config file to redirect queries for all of those domains to a given IP

import sys

if len(sys.argv) != 2:
	print "Usage: ./dnsmasq-config.py <netflix-proxy-ip>"
	sys.exit(1)

lines = file('data/zones.override').readlines()
output = 'server='

for line in lines:
	if line[0:6] == 'zone "':
		domain = line[6:line.index('."')]
		output += '/'+domain

output += '/'+sys.argv[1]
print output
