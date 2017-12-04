#!/usr/bin/env bash

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

# globals
CWD=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
[ -e "${CWD}/scripts/globals" ] && . ${CWD}/scripts/globals

# import functions
[ -e "/lib/lsb/init-functions" ] && . /lib/lsb/init-functions
[ -e "${CWD}/scripts/functions" ] && . ${CWD}/scripts/functions

log_action_begin_msg "checking if cURL is installed"
which curl > /dev/null
log_action_end_msg $?

log_action_begin_msg "checking if Docker is installed"
which docker > /dev/null
log_action_end_msg $?

log_action_begin_msg "checking if sudo is installed"
which sudo > /dev/null
log_action_end_msg $?

log_action_begin_msg "checking if dig is installed"
which dig > /dev/null
log_action_end_msg $?

log_action_begin_msg "checking OS compatibility"
if [[ $(cat /etc/os-release | grep '^ID=') =~ ubuntu ]]\
  || [[ $(cat /etc/os-release | grep '^ID=') =~ debian ]]; then
    true
    log_action_end_msg $?
else
    false
    log_action_end_msg $?
    exit 1
fi

# obtain the interface with the default gateway
IFACE=$(get_iface 4)

# obtain IP address of the Internet facing interface
IPADDR=$(get_ipaddr)
EXTIP=$(get_ext_ipaddr 4)

IPV6=0
if cat /proc/net/if_inet6 | grep -v lo | grep -v fe80 > /dev/null\
  && $(which curl) mgmt.unzoner.com --fail --silent -6 > /dev/null; then
    IPV6=1
    IPADDR6=$(get_ipaddr6)
    EXTIP6=$(get_ext_ipaddr 6)
fi

# obtain client (home) ip address and address family
CLIENTIP=$(get_client_ipaddr)

# get the current date
DATE=$(/bin/date +'%Y%m%d')

# display usage
usage() {
    echo "Usage: $0 [-r 0|1] [-b 0|1] [-c <ip>] [-z 0|1]" 1>&2;\
    printf "\t-r\tenable (1) or disable (0) DNS recursion (default: 1)\n";\
    printf "\t-b\tgrab docker images from repository (0) or build locally (1) (default: 0)\n";\
    printf "\t-c\tspecify client-ip instead of being taken from ssh_connection\n";\
    printf "\t-z\tenable caching resolver (default: 0)\n";\
    exit 1;
}

# process options
while getopts ":r:b:c:z" o; do
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
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [[ -z "${r}" ]]; then r=1; fi
if [[ -z "${b}" ]]; then b=0; fi
if [[ -z "${z}" ]]; then z=0; fi
if [[ -n "${c}" ]]; then CLIENTIP="${c}"; fi

IS_CLIENT_IPV4=0
if ! is_ipv4 ${CLIENTIP}; then IS_CLIENT_IPV4=1; fi

IS_CLIENT_IPV6=1
if [[ "${IPV6}" == '1' ]]; then
    if is_ipv6 ${CLIENTIP}; then
        IS_CLIENT_IPV6=0
    fi
fi

# diagnostics info
debug="$0: recursion=${r} build=${b} resolver=${z} client=${CLIENTIP} is_client_ipv4=${IS_CLIENT_IPV4} ipaddr=${IPADDR} extip=${EXTIP}"

if [[ "${IPV6}" == '1' ]]; then
    debug_v6="$0: is_client_ipv6=${IS_CLIENT_IPV6} ipaddr6=${IPADDR6} extip6=${EXTIP6}"
fi

sudo touch ${CWD}/netflix-proxy.log
log_action_begin_msg "log diagnostics info"
printf "recursion=${r} build=${b} resolver=${z}\n"
printf "client=${CLIENTIP} local=${IPADDR} public=${EXTIP}\n"
printf "${debug}\n" &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ ${debug_v6} ]]; then
    log_action_begin_msg "log diagnostics info (IPv6)"
    printf "local6=${IPADDR6} public6=${EXTIP6}\n"
    printf "${debug_v6}\n" &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

# prepare BIND config
if [[ "${r}" == '0' ]]; then
    log_action_begin_msg "disabling DNS recursion"
    printf "\t\tallow-recursion { none; };\n\t\trecursion no;\n\t\tadditional-from-auth no;\n\t\tadditional-from-cache no;\n"\
      | sudo tee ${CWD}/docker-bind/named.recursion.conf &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
else
    log_action_begin_msg "enabling DNS recursion"
    printf "\t\tallow-recursion { trusted; };\n\t\trecursion yes;\n\t\tadditional-from-auth yes;\n\t\tadditional-from-cache yes;\n"\
      | sudo tee ${CWD}/docker-bind/named.recursion.conf &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

# switch to working directory
pushd ${CWD} &>> ${CWD}/netflix-proxy.log

# configure iptables
if [[ -n "${CLIENTIP}" ]]; then
    log_action_begin_msg "authorising clientip=${CLIENTIP} on iface=${IFACE}"
    if [[ "${IS_CLIENT_IPV4}" == '0' ]]; then
        sudo iptables -t nat -A PREROUTING -s ${CLIENTIP}/32 -i ${IFACE} -j ACCEPT
    fi
    if [[ "${IS_CLIENT_IPV6}" == '0' ]]; then
        sudo ip6tables -t nat -A PREROUTING -s ${CLIENTIP}/128 -i ${IFACE} -j ACCEPT
    fi
    log_action_end_msg $?
else
    log_action_cont_msg "unable to resolve and authorise client ip"
fi

log_action_begin_msg "adding IPv4 iptables rules"
sudo iptables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080\
  && sudo iptables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080\
  && sudo iptables -t nat -A PREROUTING -i ${IFACE} -p udp --dport 53 -j REDIRECT --to-port 5353\
  && sudo iptables -A INPUT -p icmp -j ACCEPT\
  && sudo iptables -A INPUT -i lo -j ACCEPT\
  && sudo iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\
  && sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\
  && sudo iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT\
  && sudo iptables -A INPUT -p udp -m udp --dport 5353 -j ACCEPT\
  && sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\
  && sudo iptables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\
  && sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\
  && sudo iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
log_action_end_msg $?

log_action_begin_msg "adding IPv6 iptables rules"
sudo ip6tables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080\
  && sudo ip6tables -t nat -A PREROUTING -i ${IFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080\
  && sudo ip6tables -t nat -A PREROUTING -i ${IFACE} -p udp --dport 53 -j REDIRECT --to-port 5353\
  && sudo ip6tables -A INPUT -p ipv6-icmp -j ACCEPT\
  && sudo ip6tables -A INPUT -i lo -j ACCEPT\
  && sudo ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\
  && sudo ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\
  && sudo ip6tables -A INPUT -p udp -m udp --dport 53 -j ACCEPT\
  && sudo ip6tables -A INPUT -p udp -m udp --dport 5353 -j ACCEPT\
  && sudo ip6tables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT\
  && sudo ip6tables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\
  && sudo ip6tables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\
  && sudo ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
log_action_end_msg $?
	
# check if public IPv6 access is available
log_action_begin_msg "creating Docker and sniproxy configuration templates"
sudo cp ${CWD}/docker-sniproxy/sniproxy.conf.template ${CWD}/docker-sniproxy/sniproxy.conf &>> ${CWD}/netflix-proxy.log\
  && sudo cp ${CWD}/docker-compose.yml.template ${CWD}/docker-compose.yml &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "disabling Docker iptables control"
cp ${CWD}/daemon.json /etc/docker/
log_action_end_msg $?

if [[ "${IPV6}" == '1' ]]; then
    log_action_begin_msg "enabling sniproxy IPv6 priority"
    printf "\nresolver {\n  nameserver 8.8.8.8\n  mode ipv6_first\n}\n"\
      | sudo tee -a ${CWD}/docker-sniproxy/sniproxy.conf &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
        
    log_action_begin_msg "adding IPv6 iptables rules"
    sudo ip6tables -A INPUT -p icmpv6 -j ACCEPT\
      && sudo ip6tables -A INPUT -i lo -j ACCEPT\
      && sudo ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\
      && sudo ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\
      && sudo ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited\
      && sudo ip6tables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
    log_action_end_msg $?
else
    log_action_begin_msg "configuring sniproxy and Docker"
    printf "\nresolver {\n  nameserver 8.8.8.8\n  mode ipv4_only\n}\n"\
      | sudo tee -a ${CWD}/docker-sniproxy/sniproxy.conf &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

if [[ ${z} == 1 ]]; then
    log_action_begin_msg "enabling caching-resolver support"
    printf "  links:\n    - caching-resolver\n"\
      | sudo tee -a ${CWD}/docker-compose.yml &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi
    
log_action_begin_msg "installing iptables|netfilter-persistent service"
echo iptables-persistent iptables-persistent/autosave_v4 boolean true\
  | sudo debconf-set-selections &>> ${CWD}/netflix-proxy.log\
  && echo iptables-persistent iptables-persistent/autosave_v6 boolean true\
  | sudo debconf-set-selections &>> ${CWD}/netflix-proxy.log\
  && sudo apt-get -y install iptables-persistent &>> ${CWD}/netflix-proxy.log
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
    sudo $(which sed) -i.bak "s/ and net-device-up IFACE!=lo)/ and net-device-up IFACE!=lo and started ${SERVICE}-persistent)/" /etc/init/docker.conf &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi
	
if [[ ${SERVICE} == "iptables" ]]; then
    if [ ! -f "/etc/init.d/iptables-persistent.bak" ]; then
        log_action_begin_msg "updating iptables-persistent init script"
        sudo $(which sed) -i.bak '/load_rules$/{N;s/load_rules\n\t;;/load_rules\n\tinitctl emit -n started JOB=iptables-persistent\n\t;;/}' /etc/init.d/iptables-persistent &>> ${CWD}/netflix-proxy.log\
          && sudo $(which sed) -i'' 's/stop)/stop)\n\tinitctl emit stopping JOB=iptables-persistent/' /etc/init.d/iptables-persistent &>> ${CWD}/netflix-proxy.log
        log_action_end_msg $?
    fi
fi

log_action_begin_msg "saving iptables rules"
sudo service ${SERVICE}-persistent save &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "creating zones.override from template"
sudo cp ${CWD}/docker-bind/zones.override.template ${CWD}/docker-bind/zones.override &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ "${IPV6}" == '1' ]] && [[ ${EXTIP6} ]]; then
    log_action_begin_msg "updating db.override extip=${EXTIP} extip6=${EXTIP6} date=${DATE}"
else
    log_action_begin_msg "updating db.override extip=${EXTIP} date=${DATE}"
fi
sudo cp ${CWD}/docker-bind/db.override.template ${CWD}/docker-bind/db.override &>> ${CWD}/netflix-proxy.log

if [[ "${IPV6}" == '1' ]] && [[ -n "${EXTIP6}" ]]; then
cat << EOF >> ${CWD}/docker-bind/db.override
ns1 IN  AAAA ::1
@   IN  AAAA ::1
*   IN  AAAA ::1
EOF
fi

if [[ -n "${EXTIP}" ]]; then
    sudo $(which sed) -i "s/127.0.0.1/${EXTIP}/g" ${CWD}/docker-bind/db.override &>> ${CWD}/netflix-proxy.log
fi

if [[ -n "${EXTIP6}" ]]; then
    sudo $(which sed) -i "s/::1/${EXTIP6}/g" ${CWD}/docker-bind/db.override &>> ${CWD}/netflix-proxy.log
fi

sudo $(which sed) -i "s/YYYYMMDD/${DATE}/g" ${CWD}/docker-bind/db.override &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "installing python-pip and docker-compose"
sudo apt-get -y update &>> ${CWD}/netflix-proxy.log\
  && sudo apt-get -y install python-pip sqlite3 &>> ${CWD}/netflix-proxy.log\
  && sudo pip install --upgrade pip &>> ${CWD}/netflix-proxy.log\
  && sudo pip install setuptools docker-compose &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "configuring netflix-proxy-admin backend"
sudo $(which pip) install -r ${CWD}/auth/requirements.txt &>> ${CWD}/netflix-proxy.log\
  && PLAINTEXT=$(${CWD}/auth/pbkdf2_sha256_hash.py | awk '{print $1}')\
  && HASH=$(${CWD}/auth/pbkdf2_sha256_hash.py ${PLAINTEXT} | awk '{print $2}')\
  && sudo cp ${CWD}/auth/db/auth.default.db ${CWD}/auth/db/auth.db &>> ${CWD}/netflix-proxy.log\
  && sudo $(which sqlite3) ${CWD}/auth/db/auth.db "UPDATE users SET password = '${HASH}' WHERE ID = 1;" &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "configuring netflix-proxy-admin reverse-proxy"
sudo cp ${CWD}/Caddyfile.template ${CWD}/Caddyfile &>> ${CWD}/netflix-proxy.log\
  && printf "proxy / localhost:${SDNS_ADMIN_PORT} {\n    except /static\n    header_upstream Host {host}\n    header_upstream X-Forwarded-For {remote}\n    header_upstream X-Real-IP {remote}\n    header_upstream X-Forwarded-Proto {scheme}\n}\n"\
  | sudo tee -a ${CWD}/Caddyfile &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "creating cron scripts"
sudo cp ${CWD}/crond.template /etc/cron.d/netflix-proxy &>> ${CWD}/netflix-proxy.log\
  && sudo $(which sed) -i'' "s#{{CWD}}#${CWD}#g" /etc/cron.d/netflix-proxy &>> ${CWD}/netflix-proxy.log\
  && sudo service cron restart &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ "${b}" == '1' ]]; then
    log_action_begin_msg "building docker containers from source"
    sudo $(which docker-compose) build &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "creating and starting Docker containers"
sudo CWD=${CWD} EXTIP=${EXTIP} EXTIP6=${EXTIP6}\
  $(which docker-compose) pull &>> ${CWD}/netflix-proxy.log\
    && $(which docker-compose) up -d &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?


# configure appropriate init system
log_action_begin_msg "configuring init system"
if [[ `/sbin/init --version` =~ upstart ]]; then
    sudo cp ${CWD}/init/*.conf /etc/init/ &>> ${CWD}/netflix-proxy.log\
      && sudo service docker restart &>> ${CWD}/netflix-proxy.log\
      && sudo service netflix-proxy-admin start &>> ${CWD}/netflix-proxy.log
fi

if [[ `systemctl` =~ -\.mount ]]; then
      sudo cp ${CWD}/init/*.service /lib/systemd/system/ &>> ${CWD}/netflix-proxy.log\
        && sudo $(which sed) -i'' "s#{{CWD}}#${CWD}#g" /lib/systemd/system/netflix-proxy-admin.service &>> ${CWD}/netflix-proxy.log\
        && sudo systemctl daemon-reload &>> ${CWD}/netflix-proxy.log\
        && sudo systemctl restart docker &>> ${CWD}/netflix-proxy.log\
        && sudo systemctl enable netflix-proxy-admin &>> ${CWD}/netflix-proxy.log\
        && sudo systemctl enable systemd-networkd &>> ${CWD}/netflix-proxy.log\
        && sudo systemctl enable systemd-networkd-wait-online &>> ${CWD}/netflix-proxy.log\
        && sudo systemctl start netflix-proxy-admin &>> ${CWD}/netflix-proxy.log
fi
log_action_end_msg $?

log_action_begin_msg "reloading ipables rules"
sudo service ${SERVICE}-persistent reload &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

log_action_begin_msg "testing DNS"
with_backoff $(which dig) -4\
  +time=${TIMEOUT} ${NETFLIX_HOST} @${EXTIP} &>> ${CWD}/netflix-proxy.log\
  || with_backoff $(which dig) -4\
  +time=${TIMEOUT} ${NETFLIX_HOST} @${IPADDR} &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] && [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing DNS ipv6"
    with_backoff $(which dig) -6\
      +time=${TIMEOUT} ${NETFLIX_HOST} @${EXTIP6} &>> ${CWD}/netflix-proxy.log\
      || with_backoff $(which dig) -6\
      +time=${TIMEOUT} ${NETFLIX_HOST} @${IPADDR6} &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "testing proxy (OpenSSL)"
printf "GET / HTTP/1.1\n"\
  | with_backoff $(which timeout) ${TIMEOUT}\
  $(which openssl) s_client -CApath /etc/ssl/certs\
  -servername ${NETFLIX_HOST}\
  -connect ${EXTIP}:443 -tls1_2 &>> ${CWD}/netflix-proxy.log\
  || printf "GET / HTTP/1.1\n"\
  | with_backoff $(which timeout) ${TIMEOUT}\
  $(which openssl) s_client -CApath /etc/ssl/certs\
  -servername ${NETFLIX_HOST}\
  -connect ${IPADDR}:443 -tls1_2 &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] || [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing proxy (OpenSSL) ipv6"
    printf "GET / HTTP/1.1\n"\
      | with_backoff $(which timeout) ${TIMEOUT}\
      $(which openssl) s_client -CApath /etc/ssl/certs\
      -servername ${NETFLIX_HOST}\
      -connect ip6-localhost:443 -tls1_2 &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

log_action_begin_msg "testing proxy (cURL)"
with_backoff $(which curl) --silent -4\
  --fail -o /dev/null -L\
  -H "Host: ${NETFLIX_HOST}" http://${EXTIP} &>> ${CWD}/netflix-proxy.log\
  || with_backoff $(which curl) --silent -4\
  --fail -o /dev/null -L\
  -H "Host: ${NETFLIX_HOST}" http://${IPADDR} &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] && [[ -n "${IPADDR6}" ]]; then
    log_action_begin_msg "testing proxy (cURL) ipv6"
    with_backoff $(which curl) --silent -6\
      --fail -o /dev/null -L\
      -H "Host: ${NETFLIX_HOST}" http://ip6-localhost &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

printf "\nnetflix-proxy-admin site=http://${EXTIP}:8080/ credentials=\e[1madmin:${PLAINTEXT}\033[0m\n"
log_action_begin_msg "testing netflix-proxy admin site"
(with_backoff $(which curl) --silent -4\
  --fail http://${EXTIP}:8080/ &>> ${CWD}/netflix-proxy.log\
  || with_backoff $(which curl) --silent -4\
  --fail http://${IPADDR}:8080/) &>> ${CWD}/netflix-proxy.log\
  && with_backoff $(which curl) --silent -4\
  --fail http://localhost:${SDNS_ADMIN_PORT}/ &>> ${CWD}/netflix-proxy.log
log_action_end_msg $?

if [[ -n "${EXTIP6}" ]] && [[ -n "${IPADDR6}" ]]; then
    printf "\nnetflix-proxy-admin site=http://${EXTIP6}:8080/ credentials=\e[1madmin:${PLAINTEXT}\033[0m\n"
    log_action_begin_msg "testing netflix-proxy admin site ipv6"
    with_backoff $(which curl) --silent -6\
      --fail http://ip6-localhost:8080/ &>> ${CWD}/netflix-proxy.log
    log_action_end_msg $?
fi

# change back to original directory
popd &>> ${CWD}/netflix-proxy.log

if [[ "${IPV6}" == '1' ]]; then
    printf "IPv6=\e[32mEnabled\033[0m\n"
else
    printf "\e[1mWARNING:\033[0m IPv6=\e[31mDisabled\033[0m\n"
fi

if [[ ${z} == 1 ]]; then
    printf "caching-resolver=\e[32mEnabled\033[0m\n"
else
    printf "caching-resolver=\e[33mDisabled\033[0m\n"
fi

# DO NOT change the text between these lines
printf "Change your DNS to ${EXTIP} and start watching Netflix out of region.\n"
# DO NOT change the text between these lines

printf "\e[33mNote\033[0m: get \e[1mhttp://unzoner.com\033[0m if your app/service no longer works with DNS based solutions.\n"
printf "\e[32mDone.\033[0m\n"
