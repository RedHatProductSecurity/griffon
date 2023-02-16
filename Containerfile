FROM quay.io/fedora/fedora:37

LABEL maintainer="Red Hat Product Security Dev - Red Hat, Inc." \
      vendor="Red Hat Product Security Dev - Red Hat, Inc." \
      summary="Red Hat Product Security CLI." \
      distribution-scope="public"

ARG PIP_INDEX_URL="https://pypi.org/simple"
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_INDEX_URL="${PIP_INDEX_URL}" \
    REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE}"

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

# TODO - this will be removed once we ship corgi_bindings to pypi
RUN  pip install pip install -e "git+https://github.com/RedHatProductSecurity/component-registry-bindings#egg=component_registry_bindings"

WORKDIR /opt/app-root/src/

COPY ./requirements ./requirements

# Install Python package dependencies from requirements file passed in PIP_REQUIREMENT (local
# docker-compose may override this in the build step).
RUN pip3 install -r "./requirements/base.txt"

# TODO - remove once corgi-bindings is in pypi
RUN pip3 install -e "${CORGI_BINDINGS_PIP_URI}"

# Limit copied files to only the ones required to run the app
COPY ./files/krb5.conf /etc
COPY ./*.sh ./*.py ./
COPY ./griffon ./griffon
COPY ./README.md ./README.md

RUN pip3 install .

# TODO - we need to grok 'autocompletion' in a container context

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root

ENTRYPOINT ["griffon"]
