# Dockerfile for BIND DNS on CentOS

FROM centos

MAINTAINER anton.belodedenko@gmail.com

ADD named.conf /etc/named.conf

RUN yum -y install bind bind-chroot

RUN chown -hR named:named /var/named

CMD ["/usr/sbin/named", "-u", "named", "-c", "/etc/named.conf", "-f"]
