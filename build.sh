#!/usr/bin/env bash

# Note, this script assumes Ubuntu or Debian Linux and it will most likely fail on any other distribution.

# bomb on any error
set -e

# gobals
TIMEOUT=10
BUILD_ROOT="/opt/netflix-proxy"
SDNS_ADMIN_PORT=43867
HE_TUNNEL_INDEX=1
HE_IFACE=he-ipv6
NETFLIX_HOST=netflix.com

# import functions
[ -e "/lib/lsb/init-functions" ] && . /lib/lsb/init-functions
. ${BUILD_ROOT}/scripts/functions

# obtain the interface with the default gateway
IFACE=$(get_iface)

# obtain IP address of the Internet facing interface
IPADDR=$(get_ipaddr)
EXTIP=$(get_ext_ipaddr)

# obtain client (home) ip address
CLIENTIP=$(get_client_ipaddr)

# get the current date
DATE=$(/bin/date +'%Y%m%d')

# display usage
usage() {
    echo "Usage: $0 [-r 0|1] [-b 0|1] [-c <ip>] [-z 0|1] [-u <username>] [-p <password>] [-n <1..N>] [-s <subnet>]" 1>&2; \
    printf "\t-r\tenable (1) or disable (0) DNS recursion (default: 1)\n"; \
    printf "\t-b\tgrab docker images from repository (0) or build locally (1) (default: 0)\n"; \
    printf "\t-c\tspecify client-ip instead of being taken from ssh_connection\n"; \
    printf "\t-s\tspecify IPv6 subnet for Docker (e.g. 2001:470:abcd:123::/64)\n"; \
    printf "\t-z\tenable caching resolver (default: 0)\n"; \
    printf "\t-u\tHE tunnel broker username\n"; \
    printf "\t-p\tHE tunnel broker password\n"; \
    printf "\t-n\tHE tunnel index (default: ${HE_TUNNEL_INDEX})\n"; \
    exit 1;
}

# process options
while getopts ":r:b:c:z:s:u:p:n:" o; do
    case "${o}" in
        r)
            r=${OPTARG}
            ((r == 0|| r == 1)) || usage
            ;;
        b)
            b=${OPTARG}
            ((b == 0|| b == 1)) || usage
            ;;
        z)
            z=${OPTARG}
            ((z == 0|| z == 1)) || usage
            ;;
        c)
            c=${OPTARG}
            ;;
        s)
            s=${OPTARG}
            ;;
        u)
            u=${OPTARG}
            ;;
        p)
            p=${OPTARG}
            ;;
        n)
            n=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [[ -z "${r}" ]]; then
    r=1
fi

if [[ -z "${b}" ]]; then
    b=0
fi

if [[ -z "${z}" ]]; then
    z=0
fi

if [[ -n "${c}" ]]; then
    CLIENTIP="${c}"
fi

if [[ -n "${s}" ]]; then
    IPV6_SUBNET="${s}"
fi

if [[ -n "${u}" ]]; then
    HE_TUNNEL_BROKER_UNAME="${u}"
fi

if [[ -n "${p}" ]]; then
    HE_TUNNEL_BROKER_PASSWD="${p}"
fi

if [[ -n "${n}" ]]; then
    HE_TUNNEL_INDEX="${n}"
fi

# diagnostics info
sudo touch ${BUILD_ROOT}/netflix-proxy.log
printf "resolved params: clientip=${CLIENTIP} ipaddr=${IPADDR} extip=${EXTIP}\n"
printf "cmd: $0 -r=${r} -b=${b} -s=${IPV6_SUBNET} -z=${z} -n=${HE_TUNNEL_INDEX} -u=${HE_TUNNEL_BROKER_UNAME} -p [secret]\n\n"

# automatically enable IPv6 (tunnel)
if [[ -n "${HE_TUNNEL_BROKER_UNAME}" ]] && [[ -n "${HE_TUNNEL_BROKER_PASSWD}" ]]; then
    log_action_begin_msg "disabling native IPv6 on ${IFACE}"
    sudo sysctl -w net.ipv6.conf.${IFACE}.disable_ipv6=1 && \
      printf "net.ipv6.conf.${IFACE}.disable_ipv6=1\n" | sudo tee -a /etc/sysctl.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo sysctl -p &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    log_action_begin_msg "installing XPath"
    apt-get -y install libxml-xpath-perl &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    log_action_begin_msg "enabling ${HE_IFACE} interface"
    mkdir -p /etc/network/interfaces.d &>> ${BUILD_ROOT}/netflix-proxy.log && \
      printf "source-directory interfaces.d\n" | sudo tee -a /etc/network/interfaces &>> ${BUILD_ROOT}/netflix-proxy.log && \
      add_tunnel_iface_config ${HE_TUNNEL_BROKER_UNAME} ${HE_TUNNEL_BROKER_PASSWD} ${HE_TUNNEL_INDEX} &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    IPV6_SUBNET=$(get_tunnel_routed64 ${HE_TUNNEL_INDEX})
    CLIENTV4=$(get_tunnel_clientv4 ${HE_TUNNEL_INDEX})
    if [[ ${EXTIP} == ${CLIENTV4} ]]; then 
        log_action_cont_msg "bringing up IPv6 tunnel"
        sudo ifup ${HE_IFACE} &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
    else
        log_action_cont_msg "tunnel endpoint clientv4=${CLIENTV4} does not match extip=${EXTIP}"
        log_action_cont_msg "attempting to update tunnel configuration"
        # https://forums.he.net/index.php?topic=3153.0
        with_backoff $(which curl) -4 --fail \
          "https://${HE_TUNNEL_BROKER_UNAME}:${HE_TUNNEL_BROKER_PASSWD}@ipv4.tunnelbroker.net/nic/update?hostname=${HE_TUNNEL_INDEX}&myip=${EXTIP}" &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
        log_action_cont_msg "bringing up IPv6 tunnel"
        sudo ifup ${HE_IFACE} &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
    fi
    log_action_cont_msg "testing IPv6 tunnel (ICMP)"
    with_backoff $(which ping6) -c 3 -I ${HE_IFACE} ${NETFLIX_HOST} &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    log_action_cont_msg "testing IPv6 tunnel (HTTP/S)"
    with_backoff $(which curl) -6 --fail -L ${NETFLIX_HOST} &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $? 
fi

# prepare BIND config
if [[ ${r} == 0 ]]; then
    printf "disabling DNS recursion...\n"
    printf "\t\tallow-recursion { none; };\n\t\trecursion no;\n\t\tadditional-from-auth no;\n\t\tadditional-from-cache no;\n" | sudo tee ${BUILD_ROOT}/docker-bind/named.recursion.conf
else
    printf "WARNING: enabling DNS recursion...\n"
    printf "\t\tallow-recursion { trusted; };\n\t\trecursion yes;\n\t\tadditional-from-auth yes;\n\t\tadditional-from-cache yes;\n" | sudo tee ${BUILD_ROOT}/docker-bind/named.recursion.conf
fi

# switch to working directory
pushd ${BUILD_ROOT}

# configure iptables
printf "adding IPv4 iptables rules\n"
if [[ -n "${CLIENTIP}" ]]; then
    sudo iptables -t nat -A PREROUTING -s ${CLIENTIP}/32 -i ${IFACE} -j ACCEPT
else
    printf "WARNING: CLIENTIP variable is not set\n"
fi
sudo iptables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080 
sudo iptables -t nat -A PREROUTING -i ${IFACE} -p udp --dport 53 -j REDIRECT --to-port 5353
sudo iptables -A INPUT -p icmp -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p udp -m udp --dport 5353 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
	
# check if public IPv6 access is available
sudo cp ${BUILD_ROOT}/data/conf/sniproxy.conf.template ${BUILD_ROOT}/data/conf/sniproxy.conf && \
  sudo cp ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml.template ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml
if [[ ! $(cat /proc/net/if_inet6 | grep -v lo | grep -v fe80) =~ ^$ ]]; then
    if [[ ! $($(which curl) v6.ident.me 2> /dev/null)  =~ ^$ ]]; then
        # disable Docker iptables control and enable ipv6 dual-stack support
        # http://unix.stackexchange.com/a/164092/78029 
        # https://github.com/docker/docker/issues/9889
        IPV6=1
        printf 'enabling sniproxy IPv6 priority\n'
        printf "\nresolver {\n  nameserver 8.8.8.8\n  mode ipv6_first\n}\n" | \
          sudo tee -a ${BUILD_ROOT}/data/conf/sniproxy.conf && \
        
        printf 'enabling Docker IPv6 dual-stack support\n'
        sudo apt-get -y install sipcalc
        if [[ -z "${IPV6_SUBNET}" ]]; then
            printf 'WARNING: automatically calculating IPv6 subnet, not supported in tunnel mode\n'
            IPV6_SUBNET=$(get_docker_ipv6_subnet)
            printf "net.ipv6.conf.${IFACE}.proxy_ndp=1\n" | sudo tee -a /etc/sysctl.conf && \
            printf "net.ipv6.conf.${IFACE}.accept_ra=2\n" | sudo tee -a /etc/sysctl.conf && \
              sudo sysctl -p
        fi
        printf "DOCKER_OPTS='--iptables=false --ipv6 --fixed-cidr-v6=\"${IPV6_SUBNET}\"'\n" | \
          sudo tee -a /etc/default/docker

        printf 'adding IPv6 iptables rules\n'
        sudo ip6tables -A INPUT -p icmpv6 -j ACCEPT
        sudo ip6tables -A INPUT -i lo -j ACCEPT
        sudo ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
        sudo ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
        sudo ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
    fi
else
    # stop Docker from messing around with iptables
    IPV6=0
    printf 'WARNING: IPv4-only mode\n'
    printf "\nresolver {\n  nameserver 8.8.8.8\n}\n" | sudo tee -a ${BUILD_ROOT}/data/conf/sniproxy.conf && \
      printf "DOCKER_OPTS=\"--iptables=false\"\n" | sudo tee -a /etc/default/docker
fi

if [[ ${z} == 1 ]]; then
    printf 'enabling caching-resolver support\n'
    printf "  links:\n    - caching-resolver\n" | sudo tee -a ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml
fi
    
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get -y install iptables-persistent

# Ubuntu and Debian have different service names for iptables-persistent service
if [ -f "/etc/init.d/iptables-persistent" ]; then
    SERVICE=iptables
elif [ -f "/etc/init.d/netfilter-persistent" ]; then
    SERVICE=netfilter
fi
	
# socialise Docker with iptables-persistent: https://groups.google.com/forum/#!topic/docker-dev/4SfOwCOmw-E
if [ ! -f "/etc/init/docker.conf.bak" ]; then
    sudo $(which sed) -i.bak "s/ and net-device-up IFACE!=lo)/ and net-device-up IFACE!=lo and started ${SERVICE}-persistent)/" /etc/init/docker.conf
fi
	
if [[ ${SERVICE} == "iptables" ]]; then
    if [ ! -f "/etc/init.d/iptables-persistent.bak" ]; then
        sudo $(which sed) -i.bak '/load_rules$/{N;s/load_rules\n\t;;/load_rules\n\tinitctl emit -n started JOB=iptables-persistent\n\t;;/}' /etc/init.d/iptables-persistent && \
          sudo $(which sed) -i'' 's/stop)/stop)\n\tinitctl emit stopping JOB=iptables-persistent/' /etc/init.d/iptables-persistent
    fi
fi
sudo service ${SERVICE}-persistent save

echo "Updating db.override with EXTIP"=${EXTIP} "and DATE="${DATE}
sudo cp ${BUILD_ROOT}/data/conf/db.override.template ${BUILD_ROOT}/data/conf/db.override
sudo $(which sed) -i "s/127.0.0.1/${EXTIP}/g" ${BUILD_ROOT}/data/conf/db.override
sudo $(which sed) -i "s/YYYYMMDD/${DATE}/g" ${BUILD_ROOT}/data/conf/db.override

printf "Installing python-pip and docker-compose\n"
sudo apt-get -y update && \
  sudo apt-get -y install python-pip sqlite3 && \
  sudo pip install --upgrade pip && \
  sudo pip install docker-compose

printf "Configuring admin back-end\n"
sudo $(which pip) install -r ${BUILD_ROOT}/auth/requirements.txt && \
  sudo cp ${BUILD_ROOT}/auth/db/auth.default.db ${BUILD_ROOT}/auth/db/auth.db && \
  PLAINTEXT=$(${BUILD_ROOT}/auth/pbkdf2_sha256_hash.py | awk '{print $1}') && \
  HASH=$(${BUILD_ROOT}/auth/pbkdf2_sha256_hash.py ${PLAINTEXT} | awk '{print $2}') && \
  sudo $(which sqlite3) ${BUILD_ROOT}/auth/db/auth.db "UPDATE users SET password = '${HASH}' WHERE ID = 1;"

printf "Configuring Caddy\n"
sudo cp ${BUILD_ROOT}/Caddyfile.template ${BUILD_ROOT}/Caddyfile
printf "proxy / localhost:${SDNS_ADMIN_PORT} {\n    except /static\n    proxy_header Host {host}\n    proxy_header X-Forwarded-For {remote}\n    proxy_header X-Real-IP {remote}\n    proxy_header X-Forwarded-Proto {scheme}\n}\n" | sudo tee -a ${BUILD_ROOT}/Caddyfile

if [[ "${b}" == "1" ]]; then
    printf "Building docker containers\n"
    sudo $(which docker) build -t ab77/bind docker-bind && \
      sudo $(which docker) build -t ab77/sniproxy docker-sniproxy
fi

printf "Creating and starting Docker containers\n"
sudo BUILD_ROOT=${BUILD_ROOT} EXTIP=${EXTIP} $(which docker-compose) -f ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml up -d


# configure appropriate init system
if [[ `/sbin/init --version` =~ upstart ]]; then
    sudo cp ./upstart/* /etc/init/ && \
      sudo $(which sed) -i'' "s#{{BUILD_ROOT}}#${BUILD_ROOT}#g" /etc/init/ndp-proxy-helper.conf && \
      sudo service docker restart && \
      sudo service netflix-proxy-admin start && \
      sudo service ndp-proxy-helper start
elif [[ `systemctl` =~ -\.mount ]]; then
    sudo mkdir -p /lib/systemd/system/docker.service.d && \
      printf '[Service]\nEnvironmentFile=-/etc/default/docker\nExecStart=\nExecStart=/usr/bin/docker daemon $DOCKER_OPTS -H fd://\n' | \
      sudo tee /lib/systemd/system/docker.service.d/custom.conf && \
      sudo cp ./systemd/* /lib/systemd/system/ && \
      sudo $(which sed) -i'' "s#{{BUILD_ROOT}}#${BUILD_ROOT}#g" /lib/systemd/system/ndp-proxy-helper.service && \
      sudo systemctl daemon-reload && \
      sudo systemctl restart docker && \
      sudo systemctl enable netflix-proxy-admin && \
      sudo systemctl enable ndp-proxy-helper && \
      sudo systemctl enable systemd-networkd && \
      sudo systemctl enable systemd-networkd-wait-online && \
      sudo systemctl start netflix-proxy-admin && \
      sudo systemctl start ndp-proxy-helper
fi
sudo service ${SERVICE}-persistent reload

# OS specific steps
if [[ `cat /etc/os-release | grep '^ID='` =~ ubuntu ]]; then
    printf "No specific steps to execute for Ubuntu at this time.\n"
elif [[ `cat /etc/os-release | grep '^ID='` =~ debian ]]; then
    printf "No specific steps to execute for Debian at this time.\n"
fi

printf "Testing DNS\n"
with_backoff $(which dig) +time=${TIMEOUT} ${NETFLIX_HOST} @${EXTIP} || \
  with_backoff $(which dig) +time=${TIMEOUT} ${NETFLIX_HOST} @${IPADDR}

printf "Testing proxy (OpenSSL)\n"
printf "GET / HTTP/1.1\n" | with_backoff $(which timeout) ${TIMEOUT} $(which openssl) s_client -CApath /etc/ssl/certs -servername ${NETFLIX_HOST} -connect ${EXTIP}:443 || \
  printf "GET / HTTP/1.1\n" | with_backoff $(which timeout) ${TIMEOUT} $(which openssl) s_client -CApath /etc/ssl/certs -servername ${NETFLIX_HOST} -connect ${IPADDR}:443
      
printf "Testing proxy (cURL)\n"
with_backoff $(which curl) --fail -o /dev/null -L -H "Host: ${NETFLIX_HOST}" http://${EXTIP} || \
  with_backoff $(which curl) --fail -o /dev/null -L -H "Host: ${NETFLIX_HOST}" http://${IPADDR}

# https://www.lowendtalk.com/discussion/40101/recommended-vps-provider-to-watch-hulu (not reliable)
printf "Testing Hulu availability\n"
printf "Hulu region(s) available to you: $(with_backoff $(which curl) -H 'Host: s.hulu.com' 'http://s.hulu.com/gc?regions=US,JP&callback=Hulu.Controls.Intl.onGeoCheckResult' 2> /dev/null | grep -Po '{(.*)}')\n"

printf "Testing netflix-proxy admin site: http://${EXTIP}:8080/ || http://${IPADDR}:8080/\n"
(with_backoff $(which curl) --fail http://${EXTIP}:8080/ || with_backoff $(which curl) --fail http://${IPADDR}:8080/) && \
  with_backoff $(which curl) --fail http://localhost:${SDNS_ADMIN_PORT}/ && \
  printf "netflix-proxy admin site credentials=\e[1madmin:${PLAINTEXT}\033[0m\n"

# change back to original directory
popd

if [[ ${IPV6} == 1 ]]; then
    printf "IPv6=\e[32mEnabled\033[0m\n"
else
    printf "\e[1mWARNING:\033[0m IPv6=\e[31mDisabled\033[0m\n"
fi

if [[ ${z} == 1 ]]; then
    printf "caching-resolver=\e[32mEnabled\033[0m\n"
else
    printf "caching-resolver=\e[33mDisabled\033[0m\n"
fi

printf "Change your DNS to ${EXTIP} and start watching Netflix out of region.\n"
printf "Done!\n"
