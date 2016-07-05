FROM fedora
MAINTAINER "Jamie Duncan"
VOLUME ["/var/tmp"]
RUN yum -y install soscleaner tar libtar
RUN yum clean all
CMD /usr/bin/soscleaner -r /var/tmp $OPTIONS $SOSREPORT 
