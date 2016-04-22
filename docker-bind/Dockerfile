FROM phusion/baseimage

MAINTAINER anton@belodedenko.me

RUN apt-get update && \
    apt-get -y install vim dnsutils curl git bind9

ADD named.conf.options /etc/bind/named.conf.options

ADD named.conf.local /etc/bind/named.conf.local

ADD named.conf.logging /etc/bind/named.conf.logging

ADD named.recursion.conf /etc/bind/named.recursion.conf

CMD ["/usr/sbin/named", "-c", "/etc/bind/named.conf", "-f"]
