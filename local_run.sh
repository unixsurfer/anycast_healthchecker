#!/bin/bash
PROGRAM=anycast-healthchecker
TEST_DIR="${PWD}/var"
DOTDIR="${TEST_DIR}/etc/"${PROGRAM}".d"
PROGRAMCONF="${TEST_DIR}/etc/"${PROGRAM}".conf"
PIDIFILE="${TEST_DIR}/var/run/"${PROGRAM}"/"${PROGRAM}".pid"
directories=("${DOTDIR}" \
"${TEST_DIR}"/var/log/"${PROGRAM}" \
"${TEST_DIR}"/var/lib/"${PROGRAM}" \
"${TEST_DIR}"/var/lib/"${PROGRAM}"/6 \
"${TEST_DIR}"/var/run/"${PROGRAM}")

echo "------------------------------------------"
echo "--------create directory structure--------"
echo "------------------------------------------"
for dir in ${directories[@]}; do
    if [ ! -d "${dir}" ]; then
        mkdir -v -p "${dir}"
    fi
done

echo "------------------------------------------"
echo "---------------create config--------------"
echo "------------------------------------------"
if [ ! -e ${PROGRAMCONF}  ]; then
    echo "${PROGRAMCONF}"
    cat <<EOT > "${PROGRAMCONF}"
[DEFAULT]
interface        = lo

[daemon]
pidfile                 = ${PIDIFILE}
loglevel                = debug
log_maxbytes            = 104857600
log_backups             = 8
log_file                = ${TEST_DIR}/var/log/anycast-healthchecker/anycast-healthchecker.log
stderr_file             = ${TEST_DIR}/var/log/anycast-healthchecker/stderr.log

ipv4                    = true
bird_conf               = ${TEST_DIR}/var/lib/anycast-healthchecker/anycast-prefixes.conf
bird_variable           = ACAST_PS_ADVERTISE
bird_keep_changes       = true
bird_changes_counter    = 6
bird_reconfigure_cmd    = /usr/bin/sudo /usr/sbin/birdc configure
dummy_ip_prefix         = 10.189.200.255/32

ipv6                    = true
bird6_conf              = ${TEST_DIR}/var/lib/anycast-healthchecker/6/anycast-prefixes.conf
bird6_variable          = ACAST6_PS_ADVERTISE
dummy_ip6_prefix        = 2001:db8::1/128
bird6_reconfigure_cmd   = sudo /usr/sbin/birdc6 configure
bird6_keep_changes      = true
bird6_changes_counter   = 6
EOT
fi

echo "------------------------------------------"
echo "--------create service checks-------------"
echo "------------------------------------------"
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

if [ ! -e ${DOTDIR}/fooIPv6.bar.com.conf ]; then
    cat <<EOT > ${DOTDIR}/fooIPv6.bar.com.conf
[foo1IPv6.bar.com]
check_cmd         = /usr/bin/curl --fail -o /dev/null 'http://[fd12:aba6:57db:ffff::1]:8888'
check_timeout     = 5
check_rise        = 2
check_fail        = 2
check_disabled    = false
on_disabled       = withdraw
ip_prefix         = fd12:aba6:57db:ffff::1/128
ip_check_disabled = false
EOT
fi

if [ ! -e ${DOTDIR}/foo1IPv6.bar.com.conf ]; then
    cat <<EOT > ${DOTDIR}/foo1IPv6.bar.com.conf
[foo1IPv6.bar.com]
check_cmd         = /usr/bin/curl --fail -o /dev/null 'http://[fd12:aba6:57db:ffff::2]:8888'
check_timeout     = 5
check_rise        = 2
check_fail        = 2
check_disabled    = false
on_disabled       = withdraw
ip_prefix         = fd12:aba6:57db:ffff::2/128
ip_check_disabled = false
EOT
fi

echo "------------------------------------------"
echo "--------installing software---------------"
echo "------------------------------------------"
python3 -m pip install .

echo "------------------------------------------"
echo "--------Assign IPs in loopback------------"
echo "------------------------------------------"
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
to_be_configured=(127.0.0.1/8 \
10.52.12.1/32 \
10.52.12.2/32 \
10.52.12.3/32 \
10.52.12.4/32 \
::1/128 \
fd12:aba6:57db:ffff::1/128 \
fd12:aba6:57db:ffff::2/128)

for ip_cidr in ${to_be_configured[@]}; do
    if ! found "${ip_cidr}" "${loopback_ips[@]}"; then
        sudo /sbin/ip addr add "${ip_cidr}" brd "${ip_cidr%%/*}" dev lo scope host && echo "Added ${ip_cidr} to loopback interface"
    fi
done

for ip_cidr in $(get_ips) ; do
    if ! found "${ip_cidr}" "${to_be_configured[@]}"; then
        sudo /sbin/ip addr del "${ip_cidr}" dev lo && echo "Removed ${ip_cidr} from loopback interface"
    fi
done

echo "------------------------------------------"
echo "---------------bird status----------------"
echo "------------------------------------------"
BIRD_PROGRAMS=(bird bird6)
for bird_daemon in ${BIRD_PROGRAMS[@]}; do
    bird_pid=$(pgrep -x "${bird_daemon}")
    if [ ! -z "${bird_pid}" ]; then
        echo "${bird_daemon} seems to be running pid:${bird_pid}"
    else
        echo "${bird_daemon} is down"
    fi
done

version=$("${PROGRAM}" -v)
echo "------------------------------------------"
echo "---------starting program-----------------"
echo "------------------------------------------"
pgrep -F "${PIDIFILE}" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Process $(cat "${PIDIFILE}") already running, killing it.."
    pkill -F "${PIDIFILE}"
    sleep 1
fi

"${PROGRAM}" -f "${PROGRAMCONF}" -d "${DOTDIR}"
if [ $? -eq 0 ]; then
    echo "anycast-healtchecker ${version} started!"
    echo 'run: nohup  python3 -m http.server --bind 10.52.12.2 8888 & nohup python3 -m http.server --bind 10.52.12.1 8888 &'
fi
