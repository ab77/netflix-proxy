#!/usr/bin/env bash

# ddns_updater.sh: Checks DDNS sites and updates the IPs if needed.
# author: patrice@brendamour.net

# Note, this script assumes Ubuntu or Debian Linux and it will most likely fail on any other distribution.

# bomb on any error
set -e

CDW=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
. ${CDW}/functions

SQLITE_DB=${CDW}/../auth/db/auth.db

# obtain the interface with the default gateway
IFACE=$(get_iface)

LIST=`sudo $(which sqlite3) ${SQLITE_DB} "SELECT domain,last_ipaddr FROM DDNS"`
for ROW in $LIST; do
        DOMAIN=`echo $ROW | awk '{split($0,a,"|"); print a[1]}'`
        OLDIP=`echo $ROW | awk '{split($0,a,"|"); print a[2]}'`
        NEWIP=`dig +short $DOMAIN`

        if [ "$OLDIP" != "$NEWIP" ]; then
                echo "$(date): Updating $DOMAIN"
                if [ -n "$OLDIP" ]; then
                        iptables -t nat -D PREROUTING -s $OLDIP/32 -i $IFACE -j ACCEPT -v && iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules
                fi
                iptables -t nat -I PREROUTING -s $NEWIP/32 -i $IFACE -j ACCEPT -v && iptables-save > /etc/iptables/rules.v4 || iptables-save > /etc/iptables.rules

                #UPDATE database
                sudo $(which sqlite3) ${SQLITE_DB} "UPDATE DDNS SET last_ipaddr = '${NEWIP}' WHERE domain = '${DOMAIN}'"
        fi
done 

exit 0