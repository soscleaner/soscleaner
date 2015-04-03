FROM fedora
# FROM rhel6
# FROM rhel7
MAINTAINER "Jamie Duncan"
VOLUME ["/var/tmp"]
WORKDIR /etc/yum.repos.d
RUN curl https://copr.fedoraproject.org/coprs/jduncan/soscleaner/repo/fedora-21/jduncan-soscleaner-fedora-21.repo
# RUN curl https://copr.fedoraproject.org/coprs/jduncan/soscleaner/repo/epel-6/jduncan-soscleaner-epel-6.repo
# RUN curl https://copr.fedoraproject.org/coprs/jduncan/soscleaner/repo/epel-7/jduncan-soscleaner-epel-7.repo
RUN yum -y install soscleaner tar libtar; yum clean all
CMD /usr/bin/soscleaner -r /var/tmp $SOSREPORT 
