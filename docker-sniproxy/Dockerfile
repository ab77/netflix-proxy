# Dockerfile for sniproxy on Fedora
FROM fedora

MAINTAINER anton@belodedenko.me

RUN dnf -y install findutils iproute net-tools udns-devel sniproxy sipcalc

ADD functions /opt/functions

ADD sniproxy.sh /opt/sniproxy.sh

CMD /opt/sniproxy.sh
