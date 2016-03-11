# Dockerfile for sniproxy on Fedora
FROM fedora

MAINTAINER anton@belodedenko.me

RUN dnf -y install udns-devel sniproxy

ADD sniproxy.sh /opt/sniproxy.sh

CMD /opt/sniproxy.sh
