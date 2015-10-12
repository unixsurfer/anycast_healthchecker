#!/bin/sh
echo "--------create directory structure--------"
mkdir -p "${PWD}"/var/var/log/anycast-healthchecker
mkdir -p "${PWD}"/var/etc/bird.d
touch "${PWD}"/var/etc/bird.d/anycast-prefixes.conf
touch "${PWD}"/var/var/log/anycast-healthchecker/anycast-healthchecker.log
touch "${PWD}"/var/var/log/anycast-healthchecker/stdout.log
touch "${PWD}"/var/var/log/anycast-healthchecker/stderr.log
mkdir -p "${PWD}"/var/etc/anycast-healthcheck.d
mkdir -p "${PWD}"/var/var/run/anycast-healthchecker
mkdir -p "${PWD}"/var/var/run/anycast-healthchecker
echo "-----------installing software------------"
python3.4 setup.py install --user
echo "-------------runing software--------------"
anycast-healthchecker -c "${PWD}"/var/etc/anycast-healthcheck.d \
    -p "${PWD}"/var/var/run/anycast-healthchecker/anycast-healthchecker.pid \
    -l debug \
    --bird-conf "${PWD}"/var/etc/bird.d/anycast-prefixes.conf \
    --bird-constant-name BIRD_CONSTANT_NAME \
    --log-file  "${PWD}"/var/var/log/anycast-healthchecker/anycast-healthchecker.log \
    --stderr-file "${PWD}"/var/var/log/anycast-healthchecker/stderr.log  \
    --stdout-file "${PWD}"/var/var/log/anycast-healthchecker/stdout.log
echo "---------------------------------------"
