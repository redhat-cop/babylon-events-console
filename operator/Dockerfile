FROM registry.access.redhat.com/ubi8:latest
  
USER 0

COPY files /operator

ENV PYTHON_VERSION=3.8.2 \
    OC_VERSION=4.2.9

RUN yum install -y \
      gcc \
      openssl-devel \
      bzip2-devel \
      libffi-devel \
      make \
      nss_wrapper \
    && \
    /operator/python3-install.sh && \
    pip3 install --upgrade -r /operator/requirements.txt && \
    curl -s https://mirror.openshift.com/pub/openshift-v4/clients/ocp/${OC_VERSION}/openshift-client-linux-${OC_VERSION}.tar.gz \
    | tar zxvf - -C /bin && \
    mkdir -p /operator/nss && \
    chmod a+rwx /operator/nss

USER 1000

CMD /operator/run.sh
