#!/bin/bash

directories=("${PWD}"/var/var/log/anycast-healthchecker \
"${PWD}"/var/etc/bird.d \
"${PWD}"/var/etc/anycast-healthcheck.d \
"${PWD}"/var/var/run/anycast-healthchecker \
"${PWD}"/var/var/log/anycast-healthchecker \
"${PWD}"/var/etc/bird.d \
"${PWD}"/var/var/run/anycast-healthchecker)

files=("${PWD}"/var/etc/bird.d/anycast-prefixes.conf \
"${PWD}"/var/var/log/anycast-healthchecker/anycast-healthchecker.log \
"${PWD}"/var/var/log/anycast-healthchecker/stdout.log \
"${PWD}"/var/var/log/anycast-healthchecker/stderr.log)

echo "--------create directory structure--------"
for dir in ${directories[@]}; do
    if [ ! -d "${dir}" ]; then
        mkdir -p "${dir}"
    fi
done
echo "--------create files----------------------"
for file in ${files[@]}; do
    if [ ! -e "${file}" ]; then
        touch "${file}"
    fi
done
echo "--------create bird conf------------------"
cat <<EOT > "${PWD}"/var/etc/bird.d/anycast-prefixes.conf
# 10.189.200.255 is a dummy. It should NOT be used and REMOVED from the constant.
define ACAST_PS_ADVERTISE =
    [
        10.189.200.255/32,
        5.57.16.81/32
    ];
EOT
echo "--------create service checks------------------"
cat <<EOT > "${PWD}"/var/etc/anycast-healthcheck.d/foo.bar.com.json
{
   "name": "foo.bar.com",
   "check_cmd": "curl -A 'anycast-healthchecker' --fail --silent --connect-timeout 1 --max-time 1 -o /dev/null  http://10.52.12.1/",
   "check_interval": 10,
   "check_timeout": 5,
   "check_rise": 2,
   "check_fail": 2,
   "check_disabled": false,
   "on_disabled": "withdraw",
   "ip_prefix": "10.52.12.1/32"
}
EOT
cat <<EOT > "${PWD}"/var/etc/anycast-healthcheck.d/foo1.bar.com.json
{
   "name": "foo1.bar.com",
   "check_cmd": "curl -A 'anycast-healthchecker' --fail --silent --connect-timeout 1 --max-time 1 -o /dev/null  http://10.52.12.2/",
   "check_interval": 10,
   "check_timeout": 5,
   "check_rise": 2,
   "check_fail": 2,
   "check_disabled": false,
   "on_disabled": "withdraw",
   "ip_prefix": "10.52.12.2/32"
}
EOT
echo "--------installing software---------------"
python3.4 setup.py install --user
echo "--------Assign IPs in loopback------------"
found () {
    local query="$1"
    shift
    while [ -n "$1" ]; do
        [ "${query}" == "${1}" ] && return 0
        shift
    done
    return 1
}

get_ips () {
    /sbin/ip addr show dev lo|awk '/inet/ {print $2}'
}

while getopts "nt" option; do
    case $option in
        n) noop=1 ;;
        t) test=1 ;;
    esac
done


loopback_ips=( $(get_ips) )
configured=(127.0.0.1/8 10.52.12.1/32 10.52.12.2/32 10.52.12.3/32 10.52.12.4/32)

for ip_cidr in ${configured[@]}; do
    if ! found "${ip_cidr}" "${loopback_ips[@]}"; then
        [ -n "${test}" ] && exit 1
        [ -n "${noop}" ] || sudo /sbin/ip addr add "${ip_cidr}" brd "${ip_cidr%%/*}" dev lo scope host && echo "${noop:+[NOOP] }Added ${ip_cidr} to loopback"
    fi
done

for ip_cidr in $(get_ips) ; do
    if ! found "${ip_cidr}" "${configured[@]}"; then
        [ -n "${test}" ] && exit 1
        [ -n "${noop}" ] || sudo /sbin/ip addr del "${ip_cidr}" dev lo && echo "${noop:+[NOOP] }Removed ${ip_cidr} from loopback"
    fi
done
echo "--------runing software-------------------"
"${HOME}"/.local/bin/anycast-healthchecker -c "${PWD}"/var/etc/anycast-healthcheck.d \
    -p "${PWD}"/var/var/run/anycast-healthchecker/anycast-healthchecker.pid \
    -l debug \
    --bird-conf "${PWD}"/var/etc/bird.d/anycast-prefixes.conf \
    --bird-constant-name ACAST_PS_ADVERTISE \
    --log-file  "${PWD}"/var/var/log/anycast-healthchecker/anycast-healthchecker.log \
    --stderr-file "${PWD}"/var/var/log/anycast-healthchecker/stderr.log  \
    --stdout-file "${PWD}"/var/var/log/anycast-healthchecker/stdout.log
if [ $? -eq 0 ]; then
    echo "--------DONE!-----------------------------"
fi
