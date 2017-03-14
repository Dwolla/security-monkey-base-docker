FROM ubuntu:14.04
MAINTAINER dev@dwolla.com
USER root

ENV SECURITY_MONKEY_VERSION=v0.8.0

RUN apt-get update &&\
    apt-get -y install python-pip python-dev python-psycopg2 libpq-dev git libffi-dev &&\
    cd /usr/local/src &&\
    git clone --depth 1 --branch $SECURITY_MONKEY_VERSION https://github.com/Netflix/security_monkey.git &&\
    cd security_monkey &&\
    pip install --upgrade setuptools &&\
    python setup.py install

ADD config/config-deploy.py /usr/local/src/security_monkey/env-config/config-deploy.py
