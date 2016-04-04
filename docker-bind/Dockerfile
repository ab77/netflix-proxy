# Dockerfile for BIND DNS on CentOS

FROM centos

MAINTAINER anton@belodedenko.me

ADD named.conf /etc/named.conf

ADD named.conf.logging /etc/named.conf.logging

ADD named.recursion.conf /etc/named.recursion.conf

RUN yum -y install bind bind-chroot

RUN chown -hR named:named /var/named

RUN chown -hR named:named /etc/named*

CMD ["/usr/sbin/named", "-u", "named", "-c", "/etc/named.conf", "-f"]
