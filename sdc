#!/bin/bash

abort()
{
    echo
    echo "+--------------------------------------------------+" >&2
    echo "| An error occurred during installation.           |" >&2
    echo "| Please contact support@dataplicity.com for help  |" >&2
    echo "| Python version: $(python -V 2>&1)                    |" >&2
    if [ -f /etc/redhat-release ]; then
        echo "| OS: $(cat /etc/redhat-release)                   |" >&2
    elif [ -f /etc/lsb-release ]; then
        echo "| OS: $(lsb_release -sd)                           |" >&2
    fi
    echo "+--------------------------------------------------+" >&2
    exit 1
}


trap 'abort' 0


set -e

SERIAL_PATH=/opt/dataplicity/tuxtunnel/serial
AUTH_PATH=/opt/dataplicity/tuxtunnel/auth

echo "."
echo "This may take up to 15 minutes on some systems, but often < 30 seconds"



echo
echo " [step 1 of 5] updating system..."



set +e
# This can return a non 0 return code for unreachable PPA that shouldn't be considered an error
apt-get -qq update
set -e
apt-get -qq install supervisor
apt-get -qq install uuid
apt-get -qq install python-dev



echo " [step 2 of 5] installing Dataplicity Core..."

id -u dataplicity > /var/log/ttinstall.log || useradd dataplicity
set +e
sudo adduser dataplicity sudo > /var/log/ttinstall.log
sudo sh -c "echo \"dataplicity ALL=(ALL) NOPASSWD: /sbin/reboot\" >> /etc/sudoers"
set -e

wget -qO- https://bootstrap.pypa.io/get-pip.py -O get-pip.py
python get-pip.py > /var/log/ttinstall.log


pip install -U "dataplicity" -q --force-reinstall 2> /var/log/ttinstall.log

# pip install -U psutil -q 2> /var/log/ttinstall.log
apt-get install python-psutil


mkdir --mode=775 -p /etc/dataplicity/
mkdir --mode=775 -p /opt/dataplicity/
mkdir --mode=775 -p /opt/dataplicity/tuxtunnel
mkdir --mode=775 -p /opt/dataplicity/tuxtunnel/fw
mkdir --mode=775 -p /var/tuxtunnel
chown -R dataplicity /opt/dataplicity
chown -R dataplicity /var/tuxtunnel

echo " [step 3 of 5] installing Dataplicity..."
wget -qO- "https://dataplicity.com/download-fw/tuxtunnel/fw.zip" -O /tmp/dpfw.zip
dataplicity install /tmp/dpfw.zip -i /opt/dataplicity/tuxtunnel/fw --active --quiet

chown -R dataplicity /opt/dataplicity

set +e
REGISTER="y"
if [ -f $SERIAL_PATH ]; then

    echo
    echo "Using pre-existing serial number"
    echo "If you would like to register as a new device, run the following:"
    echo "  sudo rm $SERIAL_PATH"
    echo

    REGISTER="n"

else
    echo $(uuid) > $SERIAL_PATH
fi
set -e

if [ "$REGISTER" = "y" ]; then
    SERIAL=$(cat /opt/dataplicity/tuxtunnel/serial)
    DEVICE_NAME=$(uname -n)

    echo " [step 4 of 5] registering device '$DEVICE_NAME'..."
    RESULT=$(wget -qO- --post-data="token=cf06f31d&name=$DEVICE_NAME&serial=$SERIAL" "https://dataplicity.com/install/")

    if [ $? -ne 0 ]; then
        echo "failed to register device"
        echo "please contact support@dataplicity.com"
        exit
    else
        echo $RESULT > $AUTH_PATH
    fi
else
    echo " [step 4 of 5] skipped"
fi

echo " [step 5 of 5] starting service..."
echo """
[program:tuxtunnel]
command=dataplicity -c /opt/dataplicity/tuxtunnel/fw/current/dataplicity.conf  run
autorestart=true
redirect_stderr=true
user=dataplicity
stdout_logfile=/var/log/tuxtunnel.log
stderr_logfile=/var/log/tuxtunnel.log
""" > /etc/supervisor/conf.d/tuxtunnel.conf

dataplicity --quiet -c /opt/dataplicity/tuxtunnel/fw/current/dataplicity.conf  registersamplers
service supervisor restart &
trap : 0

echo
echo "."
echo

bash psx
