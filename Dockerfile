FROM fedora
MAINTAINER "Jamie Duncan"
VOLUME ["/var/tmp"]
WORKDIR /etc/yum.repos.d
RUN curl https://copr.fedoraproject.org/coprs/jduncan/soscleaner/repo/fedora-21/jduncan-soscleaner-fedora-21.repo
RUN yum -y install soscleaner tar libtar
RUN yum clean all
CMD /usr/bin/soscleaner -r /var/tmp $OPTIONS $SOSREPORT 
