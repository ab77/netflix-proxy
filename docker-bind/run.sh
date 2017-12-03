#!/usr/bin/env bash

set -e

ls -la /etc/bind\
  && named-checkconf\
  && for zone in $(cat /etc/bind/zones.override | grep zone | awk -F'"' '{print $2}');\
    do named-checkzone ${zone} /etc/bind/db.override; done\
  && $(which named) -c /etc/bind/named.conf -f
