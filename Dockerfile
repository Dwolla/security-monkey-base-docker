FROM ubuntu:14.04
MAINTAINER dev@dwolla.com
USER root
RUN apt-get update &&\
    apt-get -y install python-pip python-dev python-psycopg2 libpq-dev git libffi-dev &&\
    cd /usr/local/src &&\
    git clone --depth 1 --branch v0.8.0 https://github.com/Netflix/security_monkey.git &&\
    cd security_monkey &&\
    pip install --upgrade setuptools &&\
    python setup.py install
