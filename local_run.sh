#!/bin/bash
TEST_DIR="${PWD}/var"
DOTDIR="${TEST_DIR}/etc/anycast-healthchecker.d"
DAEMON=anycast-healthchecker
DAEMONCONF="${TEST_DIR}/etc/anycast-healthchecker.conf"
PIDIFILE="${TEST_DIR}/var/run/anycast-healthchecker/anycast-healthchecker.pid"
directories=("${TEST_DIR}"/var/log/anycast-healthchecker \
"${TEST_DIR}"/etc/bird.d \
"${DOTDIR}" \
"${TEST_DIR}"/var/run/anycast-healthchecker \
"${TEST_DIR}"/var/log/anycast-healthchecker \
"${TEST_DIR}"/var/lib/anycast-healthchecker \
"${TEST_DIR}"/var/run/anycast-healthchecker)

echo "--------create directory structure--------"
for dir in ${directories[@]}; do
    if [ ! -d "${dir}" ]; then
        mkdir -p "${dir}"
    fi
done
if [ ! /etc/bird.d ]; then
    sudo mkdir /etc/bird.d
fi
echo "--------create files----------------------"
if [ ! -h /etc/bird.d/anycast-prefixes.conf ] || [ "$(readlink /etc/bird.d/anycast-prefixes.conf)" != "${TEST_DIR}/var/lib/anycast-healthchecker/anycast-prefixes.conf" ]; then
    sudo ln -s "${TEST_DIR}/var/lib/anycast-healthchecker/anycast-prefixes.conf" /etc/bird.d/anycast-prefixes.conf
fi
if [ ! -e ${DAEMONCONF}  ]; then
    cat <<EOT > "${DAEMONCONF}"
[DEFAULT]
interface        = lo

[daemon]
pidfile          = ${PIDIFILE}
bird_conf        = ${TEST_DIR}/var/lib/anycast-healthchecker/anycast-prefixes.conf
bird_variable    = ACAST_PS_ADVERTISE
loglevel         = debug
log_maxbytes     = 104857600
log_backups      = 8
log_file         = ${TEST_DIR}/var/log/anycast-healthchecker/anycast-healthchecker.log
stderr_file      = ${TEST_DIR}/var/log/anycast-healthchecker/stderr.log
stdout_file      = ${TEST_DIR}/var/log/anycast-healthchecker/stdout.log
dummy_ip_prefix  = 10.189.200.255/32
bird_reconfigure_cmd = /usr/bin/sudo /usr/sbin/birdc configure
EOT
fi

if [ ! -e ${TEST_DIR}/var/lib/anycast-healthchecker/anycast-prefixes.conf ]; then
    cat <<EOT > ${TEST_DIR}/var/lib/anycast-healthchecker/anycast-prefixes.conf
# 10.189.200.255 is a dummy. It should NOT be used and REMOVED from the constant.
define ACAST_PS_ADVERTISE =
    [
        10.189.200.255/32,
        10.52.12.1
    ];
EOT
fi
echo "--------create service checks-------------"
if [ ! -e ${DOTDIR}/foo.bar.com.conf ]; then
    cat <<EOT > ${DOTDIR}/foo.bar.com.conf
[foo.bar.com]
check_cmd = curl -A 'anycast-healthchecker' --fail --silent -o /dev/null  http://10.52.12.1:8888
check_interval = 10
check_timeout = 5
check_rise = 2
check_fail = 2
check_disabled = false
on_disabled = withdraw
ip_prefix = 10.52.12.1/32
EOT
fi
if [ ! -e ${DOTDIR}/foo1.bar.com.conf ]; then
    cat <<EOT > ${DOTDIR}/foo1.bar.com.conf
[foo1.bar.com]
check_cmd = curl -A 'anycast-healthchecker' --fail --silent -o /dev/null  http://10.52.12.2:8888
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
python3 setup.py install
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
    /sbin/ip -4 addr show dev lo|awk '/inet/ {print $2}'
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
version=$("${DAEMON}" -v)
echo "---------check if Bird is running--------"
bird_pid=$(pgrep bird)
if [ ! -z ${bird_pid} ]; then
    echo "bird seems to run pid:${bird_pid}"
else
    echo "######bird seems to not be running#####"
fi
echo "--------runing ${version}----------------"
pgrep -F "${PIDIFILE}" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Process $(cat "${PIDIFILE}") already running, killing it.."
    pkill -F "${PIDIFILE}"
    sleep 1
fi
"${DAEMON}" -f "${DAEMONCONF}" -d "${DOTDIR}"
if [ $? -eq 0 ]; then
    echo "--------daemon started!-------------------"
    echo 'run: nohup  python3.4 -m http.server --bind 10.52.12.2 8888 & nohup python3.4 -m http.server --bind 10.52.12.1 8888 &'
fi
