# == Class: anycast_healthchecker::params
#
# This class manages anycast_healthchecker parameters
#
class anycast_healthchecker::params {
  $service_name          = 'anycast-healthchecker'
  $var_lib_dir           = "/var/lib/${service_name}"
  $var_lib_dir6          = "/var/lib/${service_name}/6"
  $bird_conf             = "${var_lib_dir}/anycast-prefixes.conf"
  $bird6_conf            = "${var_lib_dir6}/anycast-prefixes.conf"
  $bird_variable         = 'ACAST_PS_ADVERTISE'
  $bird6_variable        = 'ACAST6_PS_ADVERTISE'
  $bird_reconfigure_cmd  = 'sudo /usr/sbin/birdc configure'
  $bird6_reconfigure_cmd = 'sudo /usr/sbin/birdc6 configure'
  $bird_keep_changes     = false
  $bird6_keep_changes    = false
  $bird_changes_counter  = 128
  $bird6_changes_counter = 128
  $configuration_dir     = '/etc/anycast-healthchecker.d'
  $configuration_file    = '/etc/anycast-healthchecker.conf'
  $dummy_ip_prefix       = '10.189.200.255/32'
  $dummy_ip6_prefix      = '2001:db8::1/128'
  $group                 = 'healthchecker'
  $http_server           = '127.0.0.1'
  $http_server_port      = 2813
  $http_server_protocol  = 'http'
  $http_server_timeout   = 0.2
  $ipv4                  = true
  $ipv6                  = false
  $json_logging          = false
  $log_level             = 'info'
  $log_maxbytes          = 104857600
  $log_backups           = 8
  $log_dir               = '/var/log/anycast-healthchecker'
  $log_file              = "${log_dir}/anycast-healthchecker.log"
  $motd_ensure           = present
  $package_name          = 'blue-python34-anycast-healthchecker'
  $package_version       = "0.7.3-1.el${::facts['lsbmajdistrelease']}"
  $pid_dir               = "/var/run/${service_name}"
  $pidfile               = "${pid_dir}/${service_name}.pid"
  $purge_directory       = true
  $purge_ip_prefixes     = false
  $service_enable        = true
  $service_ensure        = true
  $stderr_file           = "${log_dir}/stderr.log"
  $stdout_file           = "${log_dir}/stdout.log"
  $user                  = 'healthchecker'
}
