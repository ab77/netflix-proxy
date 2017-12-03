FROM phusion/baseimage

MAINTAINER anton@belodedenko.me

RUN apt-get update && apt-get -y install --no-install-recommends\
      vim dnsutils curl git bind9

WORKDIR /etc/bind

ADD named.conf.options ./named.conf.options

ADD named.conf.local ./named.conf.local

ADD named.conf.logging ./named.conf.logging

ADD named.recursion.conf ./named.recursion.conf

CMD ["/usr/sbin/named", "-c", "/etc/bind/named.conf", "-f"]
