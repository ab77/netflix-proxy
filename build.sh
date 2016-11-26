#!/usr/bin/env bash

# Note, this script assumes Ubuntu or Debian Linux and it will most likely fail on any other distribution.

# bomb on any error
set -e

# fix terminfo
# http://ashberlin.co.uk/blog/2010/08/24/color-in-ubuntu-init-scripts/
if [[ $(infocmp | grep 'hpa=') == "" ]]; then
  (infocmp; printf '\thpa=\\E[%sG,\n' %i%p1%d) > tmp-${$}.tic && \
    tic -s tmp-$$.tic -o /etc/terminfo && \
    rm tmp-$$.tic && \
    exec ${0} $@
fi

# gobals
VERSION=2.5
TIMEOUT=10
BUILD_ROOT=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
SDNS_ADMIN_PORT=43867
HE_TUNNEL_INDEX=1
HE_IFACE=he-ipv6
NETFLIX_HOST=netflix.com

# import functions
[ -e "/lib/lsb/init-functions" ] && . /lib/lsb/init-functions
[ -e "${BUILD_ROOT}/scripts/functions" ] && . ${BUILD_ROOT}/scripts/functions

# obtain the interface with the default gateway
IFACE=$(get_iface)

# obtain IP address of the Internet facing interface
IPADDR=$(get_ipaddr)
IPADDR6=$(get_ip6addr)
EXTIP=$(get_ext_ipaddr)
EXTIP6=$(get_ext_ip6addr)

# obtain client (home) ip address and address family
CLIENTIP=$(get_client_ipaddr)
IS_IPV4=$(is_ipv4 ${CLIENTIP})
IS_IPV6=$(is_ipv6 ${CLIENTIP})

# get the current date
DATE=$(/bin/date +'%Y%m%d')

# display usage
usage() {
    echo "Usage: $0 [-r 0|1] [-b 0|1] [-c <ip>] [-z 0|1] [-u <username>] [-p <password>] [-k <update-key>] [-n <1..N>] [-s <subnet>]" 1>&2; \
    printf "\t-r\tenable (1) or disable (0) DNS recursion (default: 1)\n"; \
    printf "\t-b\tgrab docker images from repository (0) or build locally (1) (default: 0)\n"; \
    printf "\t-c\tspecify client-ip instead of being taken from ssh_connection\n"; \
    printf "\t-s\tspecify IPv6 subnet for Docker (e.g. 2001:470:abcd:123::/64)\n"; \
    printf "\t-z\tenable caching resolver (default: 0)\n"; \
    printf "\t-u\tHE tunnel broker username\n"; \
    printf "\t-p\tHE tunnel broker password\n"; \
    printf "\t-k\tHE tunnel broker update key\n"; \
    printf "\t-n\tHE tunnel index (default: ${HE_TUNNEL_INDEX})\n"; \
    exit 1;
}

# process options
while getopts ":r:b:c:z:s:u:p:n:k:v" o; do
    case "${o}" in
        v)
            printf "${VERSION}\n"
            exit
            ;;
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
        k)
            k=${OPTARG}
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
    HE_TB_UNAME="${u}"
fi

if [[ -n "${p}" ]]; then
    HE_TB_PASSWD="${p}"
fi

if [[ -n "${k}" ]]; then
    HE_TB_UPDATE_KEY="${k}"
fi

if [[ -n "${n}" ]]; then
    HE_TUNNEL_INDEX="${n}"
fi

# diagnostics info
sudo touch ${BUILD_ROOT}/netflix-proxy.log
printf "resolved params: clientip=${CLIENTIP} client_ipv4=${IS_IPV4} client_ipv6=${IS_IPV6} ipaddr=${IPADDR} ipaddr6=${IPADDR6} extip=${EXTIP} extip6=${EXTIP6}\n"
printf "cmd: $0 -r=${r} -b=${b} -s=${IPV6_SUBNET} -z=${z} -n=${HE_TUNNEL_INDEX} -u=${HE_TB_UNAME} -p [secret] -k [secret]\n\n"

# automatically enable IPv6 (tunnel)
if [[ -n "${HE_TB_UNAME}" ]] && [[ -n "${HE_TB_PASSWD}" ]]; then
    log_action_begin_msg "disabling native IPv6 on ${IFACE}"
    sudo sysctl -w net.ipv6.conf.${IFACE}.disable_ipv6=1 &>> ${BUILD_ROOT}/netflix-proxy.log && \
      printf "net.ipv6.conf.${IFACE}.disable_ipv6=1\n" | sudo tee -a /etc/sysctl.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo sysctl -p &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    log_action_begin_msg "installing XPath"
    sudo apt-get -y install libxml-xpath-perl &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    log_action_begin_msg "enabling ${HE_IFACE} interface"
    mkdir -p /etc/network/interfaces.d &>> ${BUILD_ROOT}/netflix-proxy.log && \
      printf "source-directory interfaces.d\n" | sudo tee -a /etc/network/interfaces &>> ${BUILD_ROOT}/netflix-proxy.log && \
      add_tunnel_iface_config ${HE_TB_UNAME} ${HE_TB_PASSWD} ${HE_TUNNEL_INDEX} &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?

    IPV6_SUBNET=$(get_tunnel_routed64 ${HE_TUNNEL_INDEX})
    CLIENTV4=$(get_tunnel_clientv4 ${HE_TUNNEL_INDEX})
    if [[ ${EXTIP} == ${CLIENTV4} ]]; then 
        log_action_cont_msg "bringing up IPv6 tunnel"
        sudo ifup ${HE_IFACE} &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
    else
        log_action_cont_msg "tunnel endpoint clientv4=${CLIENTV4} does not match extip=${EXTIP}"
        if [[ -n "${HE_TB_UPDATE_KEY}" ]]; then
            log_action_cont_msg "attempting to update tunnel configuration"            
            TUNNEL_ID=$(get_tunnel_id ${HE_TUNNEL_INDEX})
            # https://forums.he.net/index.php?topic=3153.0
            with_backoff $(which curl) -4 --fail \
              "https://${HE_TB_UNAME}:${HE_TB_UPDATE_KEY}@ipv4.tunnelbroker.net/nic/update?hostname=${TUNNEL_ID}" &>> ${BUILD_ROOT}/netflix-proxy.log
            log_action_end_msg $?

            log_action_cont_msg "bringing up IPv6 tunnel"
            add_tunnel_iface_config ${HE_TB_UNAME} ${HE_TB_PASSWD} ${HE_TUNNEL_INDEX} &>> ${BUILD_ROOT}/netflix-proxy.log && \
              sudo ifup ${HE_IFACE} &>> ${BUILD_ROOT}/netflix-proxy.log
            log_action_end_msg $?
        else
            log_action_cont_msg "unable to update clientv4 without update key"
            exit 1
        fi
    fi
    log_action_cont_msg "testing IPv6 tunnel (this may take a while)"
    with_backoff $(which curl) -6 --fail -L ${NETFLIX_HOST} &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $? 
fi

# prepare BIND config
if [[ ${r} == 0 ]]; then
    log_action_begin_msg "disabling DNS recursion"
    printf "\t\tallow-recursion { none; };\n\t\trecursion no;\n\t\tadditional-from-auth no;\n\t\tadditional-from-cache no;\n" | \
      sudo tee ${BUILD_ROOT}/docker-bind/named.recursion.conf &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
else
    log_action_begin_msg "enabling DNS recursion"
    printf "\t\tallow-recursion { trusted; };\n\t\trecursion yes;\n\t\tadditional-from-auth yes;\n\t\tadditional-from-cache yes;\n" | \
      sudo tee ${BUILD_ROOT}/docker-bind/named.recursion.conf &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

# switch to working directory
pushd ${BUILD_ROOT} &>> ${BUILD_ROOT}/netflix-proxy.log

# configure iptables
if [[ -n "${CLIENTIP}" ]]; then
    log_action_begin_msg "authorising clientip=${CLIENTIP} on iface=${IFACE}"
    if [[ "${IS_IPV4}" == "0" ]]; then
        sudo iptables -t nat -A PREROUTING -s ${CLIENTIP}/32 -i ${IFACE} -j ACCEPT
    fi
    if [[ "${IS_IPV6}" == "0" ]]; then
        sudo ip6tables -t nat -A PREROUTING -s ${CLIENTIP}/128 -i ${IFACE} -j ACCEPT
    fi
    log_action_end_msg $?
else
    log_action_cont_msg "unable to resolve and authorise client ip"
fi

log_action_begin_msg "adding IPv4 iptables rules"
sudo iptables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080 && \
  sudo iptables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080  && \
  sudo iptables -t nat -A PREROUTING -i ${IFACE} -p udp --dport 53 -j REDIRECT --to-port 5353 && \
  sudo iptables -A INPUT -p icmp -j ACCEPT && \
  sudo iptables -A INPUT -i lo -j ACCEPT && \
  sudo iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT && \
  sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT && \
  sudo iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT && \
  sudo iptables -A INPUT -p udp -m udp --dport 5353 -j ACCEPT && \
  sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT && \
  sudo iptables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT && \
  sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT && \
  sudo iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
log_action_end_msg $?

log_action_begin_msg "adding IPv6 iptables rules"
sudo ip6tables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080 && \
  sudo ip6tables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080  && \
  sudo ip6tables -t nat -A PREROUTING -i ${IFACE} -p udp --dport 53 -j REDIRECT --to-port 5353 && \
  sudo ip6tables -A INPUT -p ipv6-icmp -j ACCEPT && \
  sudo ip6tables -A INPUT -i lo -j ACCEPT && \
  sudo ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT && \
  sudo ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT && \
  sudo ip6tables -A INPUT -p udp -m udp --dport 53 -j ACCEPT && \
  sudo ip6tables -A INPUT -p udp -m udp --dport 5353 -j ACCEPT && \
  sudo ip6tables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT && \
  sudo ip6tables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT && \
  sudo ip6tables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT && \
  sudo ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
log_action_end_msg $?
	
# check if public IPv6 access is available
log_action_begin_msg "creating Docker and sniproxy configuration templates"
sudo cp ${BUILD_ROOT}/data/conf/sniproxy.conf.template ${BUILD_ROOT}/data/conf/sniproxy.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
  sudo cp ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml.template ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "checking IPv6 connectivity"
if [[ ! $(cat /proc/net/if_inet6 | grep -v lo | grep -v fe80) =~ ^$ ]]; then
    if [[ ! $($(which curl) v6.ident.me 2> /dev/null)  =~ ^$ ]]; then
        # disable Docker iptables control and enable ipv6 dual-stack support
        # http://unix.stackexchange.com/a/164092/78029 
        # https://github.com/docker/docker/issues/9889
        IPV6=1
        log_action_begin_msg "enabling sniproxy IPv6 priority"
        printf "\nresolver {\n  nameserver 8.8.8.8\n  mode ipv6_first\n}\n" | \
          sudo tee -a ${BUILD_ROOT}/data/conf/sniproxy.conf &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
        
        log_action_begin_msg "installing sipcalc"
        sudo apt-get -y install sipcalc &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
        
        if [[ -z "${IPV6_SUBNET}" ]]; then
            log_action_cont_msg "automatically calculating IPv6 subnet"
            IPV6_SUBNET=$(get_docker_ipv6_subnet)
            printf "net.ipv6.conf.${IFACE}.proxy_ndp=1\n" | sudo tee -a /etc/sysctl.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
            printf "net.ipv6.conf.${IFACE}.accept_ra=2\n" | sudo tee -a /etc/sysctl.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
              sudo sysctl -p &>> ${BUILD_ROOT}/netflix-proxy.log
            log_action_end_msg $?
        fi

        log_action_begin_msg "enabling Docker IPv6 dual-stack support with fixed-cidr-v6=${IPV6_SUBNET}"
        printf "DOCKER_OPTS='--iptables=false --ipv6 --fixed-cidr-v6=\"${IPV6_SUBNET}\"'\n" | \
          sudo tee -a /etc/default/docker &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?

        log_action_begin_msg "adding IPv6 iptables rules"
        sudo ip6tables -A INPUT -p icmpv6 -j ACCEPT && \
          sudo ip6tables -A INPUT -i lo -j ACCEPT && \
          sudo ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT && \
          sudo ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT && \
          sudo ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
        log_action_end_msg $?
    fi
else
    log_action_end_msg $?
    IPV6=0
    log_action_begin_msg "configuring sniproxy and Docker"
    printf "\nresolver {\n  nameserver 8.8.8.8\n}\n" | sudo tee -a ${BUILD_ROOT}/data/conf/sniproxy.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
      printf "DOCKER_OPTS=\"--iptables=false\"\n" | sudo tee -a /etc/default/docker &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

if [[ ${z} == 1 ]]; then
    log_action_begin_msg "enabling caching-resolver support"
    printf "  links:\n    - caching-resolver\n" | \
      sudo tee -a ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi
    
log_action_begin_msg "installing iptables|netfilter-persistent service"
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections &>> ${BUILD_ROOT}/netflix-proxy.log && \
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections &>> ${BUILD_ROOT}/netflix-proxy.log && \
  sudo apt-get -y install iptables-persistent &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

# Ubuntu and Debian have different service names for iptables-persistent service
if [ -f "/etc/init.d/iptables-persistent" ]; then
    SERVICE=iptables
elif [ -f "/etc/init.d/netfilter-persistent" ]; then
    SERVICE=netfilter
fi
	
# socialise Docker with iptables-persistent
# https://groups.google.com/forum/#!topic/docker-dev/4SfOwCOmw-E
if [ ! -f "/etc/init/docker.conf.bak" ]; then    
    log_action_begin_msg "socialising Docker with iptables-persistent service"
    sudo $(which sed) -i.bak "s/ and net-device-up IFACE!=lo)/ and net-device-up IFACE!=lo and started ${SERVICE}-persistent)/" /etc/init/docker.conf &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi
	
if [[ ${SERVICE} == "iptables" ]]; then
    if [ ! -f "/etc/init.d/iptables-persistent.bak" ]; then
        log_action_begin_msg "updating iptables-persistent init script"
        sudo $(which sed) -i.bak '/load_rules$/{N;s/load_rules\n\t;;/load_rules\n\tinitctl emit -n started JOB=iptables-persistent\n\t;;/}' /etc/init.d/iptables-persistent &>> ${BUILD_ROOT}/netflix-proxy.log && \
          sudo $(which sed) -i'' 's/stop)/stop)\n\tinitctl emit stopping JOB=iptables-persistent/' /etc/init.d/iptables-persistent &>> ${BUILD_ROOT}/netflix-proxy.log
        log_action_end_msg $?
    fi
fi

log_action_begin_msg "saving iptables rules"
sudo service ${SERVICE}-persistent save &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "creating zones.override from template"
sudo cp ${BUILD_ROOT}/data/conf/zones.override.template ${BUILD_ROOT}/data/conf/zones.override &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "updating db.override with extip=${EXTIP} extip6=${EXTIP6} and date=${DATE}"
sudo cp ${BUILD_ROOT}/data/conf/db.override.template ${BUILD_ROOT}/data/conf/db.override &>> ${BUILD_ROOT}/netflix-proxy.log

if [[ -n "${EXTIP}" ]]; then
    sudo $(which sed) -i "s/127.0.0.1/${EXTIP}/g" ${BUILD_ROOT}/data/conf/db.override &>> ${BUILD_ROOT}/netflix-proxy.log
fi

if [[ -n "${EXTIP6}" ]]; then
    sudo $(which sed) -i "s/::1/${EXTIP6}/g" ${BUILD_ROOT}/data/conf/db.override &>> ${BUILD_ROOT}/netflix-proxy.log
fi

sudo $(which sed) -i "s/YYYYMMDD/${DATE}/g" ${BUILD_ROOT}/data/conf/db.override &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "installing python-pip and docker-compose"
sudo apt-get -y update &>> ${BUILD_ROOT}/netflix-proxy.log && \
  sudo apt-get -y install python-pip sqlite3 &>> ${BUILD_ROOT}/netflix-proxy.log && \
  sudo pip install --upgrade pip &>> ${BUILD_ROOT}/netflix-proxy.log && \
  sudo pip install docker-compose &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "configuring netflix-proxy-admin backend"
sudo $(which pip) install -r ${BUILD_ROOT}/auth/requirements.txt &>> ${BUILD_ROOT}/netflix-proxy.log && \
  PLAINTEXT=$(${BUILD_ROOT}/auth/pbkdf2_sha256_hash.py | awk '{print $1}') && \
  HASH=$(${BUILD_ROOT}/auth/pbkdf2_sha256_hash.py ${PLAINTEXT} | awk '{print $2}') && \
  sudo cp ${BUILD_ROOT}/auth/db/auth.default.db ${BUILD_ROOT}/auth/db/auth.db &>> ${BUILD_ROOT}/netflix-proxy.log && \
  sudo $(which sqlite3) ${BUILD_ROOT}/auth/db/auth.db "UPDATE users SET password = '${HASH}' WHERE ID = 1;" &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "configuring netflix-proxy-admin reverse-proxy"
sudo cp ${BUILD_ROOT}/Caddyfile.template ${BUILD_ROOT}/Caddyfile &>> ${BUILD_ROOT}/netflix-proxy.log && \
  printf "proxy / localhost:${SDNS_ADMIN_PORT} {\n    except /static\n    proxy_header Host {host}\n    proxy_header X-Forwarded-For {remote}\n    proxy_header X-Real-IP {remote}\n    proxy_header X-Forwarded-Proto {scheme}\n}\n" | sudo tee -a ${BUILD_ROOT}/Caddyfile &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

if [[ "${b}" == "1" ]]; then
    log_action_begin_msg "building docker containers from source"
    sudo $(which docker) build -t ab77/bind docker-bind &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo $(which docker) build -t ab77/sniproxy docker-sniproxy &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "creating and starting Docker containers"
sudo BUILD_ROOT=${BUILD_ROOT} EXTIP=${EXTIP} EXTIP6=${EXTIP6} $(which docker-compose) -f ${BUILD_ROOT}/docker-compose/netflix-proxy.yaml up -d &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

# configure appropriate init system
if [[ `/sbin/init --version` =~ upstart ]]; then
    log_action_begin_msg "configuring upstart"
    sudo cp ./upstart/* /etc/init/ &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo $(which sed) -i'' "s#{{BUILD_ROOT}}#${BUILD_ROOT}#g" /etc/init/ndp-proxy-helper.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo $(which sed) -i'' "s#{{BUILD_ROOT}}#${BUILD_ROOT}#g" /etc/init/netflix-proxy-admin.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo service docker restart &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo service netflix-proxy-admin start &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo service ndp-proxy-helper start &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
elif [[ `systemctl` =~ -\.mount ]]; then
    log_action_begin_msg "configuring systemd"
    sudo mkdir -p /lib/systemd/system/docker.service.d &>> ${BUILD_ROOT}/netflix-proxy.log && \
      printf '[Service]\nEnvironmentFile=-/etc/default/docker\nExecStart=\nExecStart=/usr/bin/docker daemon $DOCKER_OPTS -H fd://\n' | \
      sudo tee /lib/systemd/system/docker.service.d/custom.conf &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo cp ./systemd/* /lib/systemd/system/ &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo $(which sed) -i'' "s#{{BUILD_ROOT}}#${BUILD_ROOT}#g" /lib/systemd/system/ndp-proxy-helper.service &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo $(which sed) -i'' "s#{{BUILD_ROOT}}#${BUILD_ROOT}#g" /lib/systemd/system/netflix-proxy-admin.service &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl daemon-reload &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl restart docker &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl enable netflix-proxy-admin &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl enable ndp-proxy-helper &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl enable systemd-networkd &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl enable systemd-networkd-wait-online &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl start netflix-proxy-admin &>> ${BUILD_ROOT}/netflix-proxy.log && \
      sudo systemctl start ndp-proxy-helper &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "reloading ipables rules"
sudo service ${SERVICE}-persistent reload &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

# OS specific steps
if [[ `cat /etc/os-release | grep '^ID='` =~ ubuntu ]]; then
    log_action_begin_msg "no specific steps to execute for Ubuntu at this time"
    log_action_end_msg $?
elif [[ `cat /etc/os-release | grep '^ID='` =~ debian ]]; then
    log_action_begin_msg "no specific steps to execute for Debian at this time"
    log_action_end_msg $?
fi

log_action_begin_msg "testing DNS"
with_backoff $(which dig) +time=${TIMEOUT} ${NETFLIX_HOST} @${EXTIP} &>> ${BUILD_ROOT}/netflix-proxy.log || \
  with_backoff $(which dig) +time=${TIMEOUT} ${NETFLIX_HOST} @${IPADDR} &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] && [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing DNS ipv6"
    with_backoff $(which dig) +time=${TIMEOUT} ${NETFLIX_HOST} @${EXTIP6} &>> ${BUILD_ROOT}/netflix-proxy.log || \
      with_backoff $(which dig) +time=${TIMEOUT} ${NETFLIX_HOST} @${IPADDR6} &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "testing proxy (OpenSSL)"
printf "GET / HTTP/1.1\n" | with_backoff $(which timeout) ${TIMEOUT} $(which openssl) s_client -CApath /etc/ssl/certs -servername ${NETFLIX_HOST} -connect ${EXTIP}:443 &>> ${BUILD_ROOT}/netflix-proxy.log || \
  printf "GET / HTTP/1.1\n" | with_backoff $(which timeout) ${TIMEOUT} $(which openssl) s_client -CApath /etc/ssl/certs -servername ${NETFLIX_HOST} -connect ${IPADDR}:443 &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] || [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing proxy (OpenSSL) ipv6"
    printf "GET / HTTP/1.1\n" | with_backoff $(which timeout) ${TIMEOUT} $(which openssl) s_client -CApath /etc/ssl/certs -servername ${NETFLIX_HOST} -connect ip6-localhost:443 &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "testing proxy (cURL)"
with_backoff $(which curl) --fail -o /dev/null -L -H "Host: ${NETFLIX_HOST}" http://${EXTIP} &>> ${BUILD_ROOT}/netflix-proxy.log || \
  with_backoff $(which curl) --fail -o /dev/null -L -H "Host: ${NETFLIX_HOST}" http://${IPADDR} &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] && [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing proxy (cURL) ipv6"
    with_backoff $(which curl) --fail -o /dev/null -L -H "Host: ${NETFLIX_HOST}" http://ip6-localhost &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "testing netflix-proxy admin site"
(with_backoff $(which curl) --fail http://${EXTIP}:8080/ &>> ${BUILD_ROOT}/netflix-proxy.log || with_backoff $(which curl) --fail http://${IPADDR}:8080/) &>> ${BUILD_ROOT}/netflix-proxy.log && \
  with_backoff $(which curl) --fail http://localhost:${SDNS_ADMIN_PORT}/ &>> ${BUILD_ROOT}/netflix-proxy.log
log_action_end_msg $?
printf "\nnetflix-proxy-admin site=http://${EXTIP}:8080/ credentials=\e[1madmin:${PLAINTEXT}\033[0m\n"

if [[ -n "${EXTIP6}" ]] && [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing netflix-proxy admin site ipv6"
    with_backoff $(which curl) --fail http://ip6-localhost:8080/ &>> ${BUILD_ROOT}/netflix-proxy.log
    log_action_end_msg $?
    printf "\nnetflix-proxy-admin site=http://${EXTIP6}:8080/ credentials=\e[1madmin:${PLAINTEXT}\033[0m\n"
fi

# change back to original directory
popd &>> ${BUILD_ROOT}/netflix-proxy.log

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

# https://www.lowendtalk.com/discussion/40101/recommended-vps-provider-to-watch-hulu
printf "Hulu region(s) available to you: $(with_backoff $(which curl) -H 'Host: s.hulu.com' 'http://s.hulu.com/gc?regions=US,JP&callback=Hulu.Controls.Intl.onGeoCheckResult' 2> /dev/null | grep -Po '{(.*)}')\n"

printf "Change your DNS to ${EXTIP} and start watching Netflix out of region.\n"
printf "Done!\n"
