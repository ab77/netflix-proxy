#!/usr/bin/env bash

set -e

ls -la /etc/bind\
  && named-checkconf\
  && named-checkzone netflix.com /etc/bind/zones.override\
  && $(which named) -c /etc/bind/named.conf -f
