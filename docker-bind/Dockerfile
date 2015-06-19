# Dockerfile for BIND DNS on CentOS

FROM centos

MAINTAINER anton.belodedenko@gmail.com

ADD named.conf /etc/named.conf

ADD named.recursion.conf /etc/named.recursion.conf

RUN yum -y install bind bind-chroot

RUN chown -hR named:named /var/named

CMD ["/usr/sbin/named", "-u", "named", "-c", "/etc/named.conf", "-f"]
