
FROM quay.io/fedora/fedora:37

LABEL maintainer="Red Hat Product Security Dev - Red Hat, Inc." \
      vendor="Red Hat Product Security Dev - Red Hat, Inc." \
      summary="Red Hat Product Security CLI." \
      distribution-scope="public"

ARG PIP_INDEX_URL
ARG ROOT_CA_URL
ARG REQUESTS_CA_BUNDLE
ARG CORGI_SERVER_URL
ARG OSIDB_SERVER_URL
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_INDEX_URL="${PIP_INDEX_URL}" \
    REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE}" \
    ROOT_CA_URL="${ROOT_CA_URL}" \
    CORGI_SERVER_URL="${CORGI_SERVER_URL}" \
    OSIDB_SERVER_URL="${OSIDB_SERVER_URL}"

RUN cd /etc/pki/ca-trust/source/anchors/ && \
    # The '| true' skips this step if the ROOT_CA_URL is unset or fails in another way
    curl -O "${ROOT_CA_URL}" | true && \
    update-ca-trust && \
    cd -

RUN dnf --nodocs --setopt install_weak_deps=false -y install \
        zsh \
        cargo \
        gcc \
        git \
        krb5-devel \
        krb5-workstation \
        libffi-devel \
        make \
        python3 \
        python3-devel \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        which \
    && dnf --nodocs --setopt install_weak_deps=false -y upgrade --security \
    && dnf clean all

WORKDIR /opt/app-root/src/

RUN pip3 install griffon

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root

ENTRYPOINT ["zsh"]
