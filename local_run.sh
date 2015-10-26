#!/bin/bash
TEST_DIR="${PWD}/var"
directories=("${TEST_DIR}"/var/log/anycast-healthchecker \
"${TEST_DIR}"/etc/bird.d \
"${TEST_DIR}"/etc/anycast-healthcheck.d \
"${TEST_DIR}"/var/run/anycast-healthchecker \
"${TEST_DIR}"/var/log/anycast-healthchecker \
"${TEST_DIR}"/etc/bird.d \
"${TEST_DIR}"/var/run/anycast-healthchecker)

echo "--------create directory structure--------"
for dir in ${directories[@]}; do
    if [ ! -d "${dir}" ]; then
        mkdir -p "${dir}"
    fi
done
echo "--------create files----------------------"
if [ ! -e ${TEST_DIR}/etc/anycast-healthchecker.conf  ]; then
    cat <<EOT > "${TEST_DIR}"/etc/anycast-healthchecker.conf
[DEFAULT]
interface        = lo

[daemon]
pidfile          = ${TEST_DIR}/var//run/anycast-healthchecker/anycast-healthchecker.pid
bird_conf        = ${TEST_DIR}/etc/bird.d/anycast-prefixes.conf
bird_variable    = ACAST_PS_ADVERTISE
loglevel         = debug
log_maxbytes     = 104857600
log_backups      = 8
log_file         = ${TEST_DIR}/var/log/anycast-healthchecker/anycast-healthchecker.log
stderr_file      = ${TEST_DIR}/var/log/anycast-healthchecker/stderr.log
stdout_file      = ${TEST_DIR}/var/log/anycast-healthchecker/stdout.log
dummy_ip_prefix  = 10.189.200.255/32
bird_reconfigure_cmd = sudo /usr/sbin/birdc configure
EOT
fi

if [ ! -e ${TEST_DIR}/etc/bird.d/anycast-prefixes.conf ]; then
    cat <<EOT > ${TEST_DIR}/etc/bird.d/anycast-prefixes.conf
# 10.189.200.255 is a dummy. It should NOT be used and REMOVED from the constant.
define ACAST_PS_ADVERTISE =
    [
        10.189.200.255/32,
    ];
EOT
fi
echo "--------create service checks-------------"
if [ ! -e ${TEST_DIR}/etc/anycast-healthcheck.d/foo.bar.com.conf ]; then
    cat <<EOT > ${TEST_DIR}/etc/anycast-healthcheck.d/foo.bar.com.conf
[foo.bar.com]
check_cmd = curl -A 'anycast-healthchecker' --fail --silent --connect-timeout 1 --max-time 1 -o /dev/null  http://10.52.12.1/
check_interval = 10
check_timeout = 5
check_rise = 2
check_fail = 2
check_disabled = false
on_disabled = withdraw
ip_prefix = 10.52.12.1/32
EOT
fi
if [ ! -e ${TEST_DIR}/etc/anycast-healthcheck.d/foo1.bar.com.conf ]; then
    cat <<EOT > ${TEST_DIR}/etc/anycast-healthcheck.d/foo1.bar.com.conf
[foo1.bar.com]
check_cmd = curl -A 'anycast-healthchecker' --fail --silent --connect-timeout 1 --max-time 1 -o /dev/null  http://10.52.12.2/
check_interval = 10
check_timeout = 5
check_rise =  2
check_fail =  2
check_disabled = false
on_disabled = withdraw
ip_prefix = 10.52.12.2/32
EOT
fi
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

loopback_ips=( $(get_ips) )
configured=(127.0.0.1/8 10.52.12.1/32 10.52.12.2/32 10.52.12.3/32 10.52.12.4/32)

for ip_cidr in ${configured[@]}; do
    if ! found "${ip_cidr}" "${loopback_ips[@]}"; then
        sudo /sbin/ip addr add "${ip_cidr}" brd "${ip_cidr%%/*}" dev lo scope host && echo "Added ${ip_cidr} to loopback"
    fi
done

for ip_cidr in $(get_ips) ; do
    if ! found "${ip_cidr}" "${configured[@]}"; then
        sudo /sbin/ip addr del "${ip_cidr}" dev lo && echo "Removed ${ip_cidr} from loopback"
    fi
done
version=$("${HOME}"/.local/bin/anycast-healthchecker -v)
echo "--------runing ${version}"
pgrep -F "${PWD}"/var/var/run/anycast-healthchecker/anycast-healthchecker.pid >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Process $(cat "${PWD}"/var/var/run/anycast-healthchecker/anycast-healthchecker.pid) already running, killing it.."
    pkill -F "${PWD}"/var/var/run/anycast-healthchecker/anycast-healthchecker.pid
fi
"${HOME}"/.local/bin/anycast-healthchecker -f "${PWD}"/var/etc/anycast-healthchecker.conf \
    -d "${PWD}"/var/etc/anycast-healthcheck.d
if [ $? -eq 0 ]; then
    echo "--------daemon started!-------------------"
fi
