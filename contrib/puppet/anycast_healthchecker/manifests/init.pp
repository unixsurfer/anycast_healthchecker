# == Class: anycast_healthchecker
#
# Installs, configures and manages anycast-healthchecker daemon
#
# === Parameters
#
# Document parameters here.
#
# [*bird_conf*]
#   File with the list of IPv6 prefixes allowed to be exported. If this file is
#   a symbolic link then the destination and the link itself must be on the same
#   mounted filesystem.
#
# [*bird6_conf*]
#   File with the list of IPv6 prefixes allowed to be exported. If this file is
#   a symbolic link then the destination and the link itself must be on the same
#   mounted filesystem.
#
# [*bird_variable*]
#   The name of the list defined in ``bird_conf``
#
# [*bird6_variable*]
#   The name of the list defined in ``bird6_conf``
#
# [*bird_reconfigure_cmd*]
#   Command to trigger a reconfiguration of IPv4 Bird daemon
#
# [*bird6_reconfigure_cmd*]
#   Command to trigger a reconfiguration of IPv6 Bird daemon
#
# [*bird_keep_changes*]
#   Keep a history of changes for ``bird_conf`` file by copying it to a directory.
#   During the startup of the daemon a directory with the name ``history`` is
#   created under the directory where ``bird_conf`` file resides. The daemon has to
#   have sufficient privileges to create that directory.
#
# [*bird6_keep_changes*]
#   Keep a history of changes for ``bird6_conf`` file by copying it to a directory.
#   During the startup of the daemon a directory with the name ``history`` is
#   created under the directory where ``bird6_conf`` file resides. The daemon has to
#   have sufficient privileges to create that directory.
#   WARNING: If keep changes is enabled for both IP protocols then the
#   ``bird_conf`` and ``bird6_conf`` **must** point to files which are stored on
#   two different directories.
#
# [*bird_changes_counter*]
#   How many ``bird_conf`` files to keep in the ``history`` directory.
#
# [*bird6_changes_counter*]
#   How many ``bird6_conf`` files to keep in the ``history`` directory.
#
# [*configuration_dir*]
#   Read settings for service checks from files under directory
#
# [*configuration_file*]
#   Read settings for the daemon from
#
# [*dummy_ip_prefix*]
#   An IP prefix in the form <IP>/<prefix length> which will be always available in
#   the list defined by ``bird_variable`` to avoid having an empty list.
#   The ``dummy_ip_prefix`` **must not** be used by any service or assigned to the
#   interface set with ``interface`` or configured anywhere on the network as
#   anycast-healthchecker **does not** perform any checks for it.
#
# [*dummy_ip6_prefix*]
#   An IPv6 prefix in the form <IPv6>/<prefix length> which will be always
#   available in the list defined by ``bird6_variable`` to avoid having an empty
#   list. The ``dummy_ip6_prefix`` **must not** be used by any service or assigned
#   to the interface set with ``interface`` or configured anywhere on the network as
#   anycast-healthchecker **does not** perform any checks for it.
#
# [*group*]
#   Set the UNIX group that anycast-healthchecker is executed.
#   WARNING: Group must exist in the system.
#
# [*http_server*]
#   Server name to send JSON logging over HTTP protocol.
#
# [*http_server_port*]
#   Port to connect
#
# [*http_server_protocol*]
#   HTTP protocol to use, either ``http`` or ``https``
#
# [*http_server_timeout*]
#   How long to wait for the server to send data before giving up, as a float number.
#   JSON messages are send using http POST requests which are executed in blocking
#   mode which means that possible long delays will make the health checks to be
#   delayed as well.
#  ``http_server_timeout`` accepts floating point numbers as values which are
#   passed to underlying request module as a single timeout which will be applied
#   to both the connect and the read timeouts.
#
# [*ipv4*]
#   Enable IPv4 support
#
# [*ipv6*]
#   Enable IPv6 support
#
# [*json_logging*]
#  ``true`` enables JSON logging ``false`` disables it.
#
# [*user*]
#   Set the UNIX user that anycast-healthchecker is executed
#   WARNING: User must exist in the system.
#
# === Examples
#
#    $user  = 'healthchecker'
#    $group = 'healthchecker'
#    $bird_variable  = 'ACAST_PS_ADVERTISE'
#    $bird6_variable = 'ACAST_PS_ADVERTISE_IPV6'
#    realize ( Group[$group] )
#    realize ( User[$user] )
#    class { 'anycast_healthchecker':
#      package_version => '0.7.0-1.el7',
#      bird_conf       => '/etc/bird.d/4/anycast-prefixes.conf',
#      bird6_conf      => '/etc/bird.d/6/anycast-prefixes.conf',
#      bird_variable   => $bird_variable,
#      bird6_variable  => $bird6_variable,
#      user            => $user,
#      group           => $group,
#      json_logging    => true,
#      ipv6            => true,
#      var_lib_dir     => '/var/lib/anycast-healthchecker',
#      var_lib_dir6    => '/var/lib/anycast-healthchecker/6',
#      require         => [
#        User[$user],
#        Group[$group],
#      ],
#    }
#    ::bird2::config::variable{
#      $bird_variable:
#        scope     => 'ipv4',
#        replace   => false,
#        file_name => 'anycast-prefixes',
#        value     => [ '10.189.200.255/32', ];
#    }
#    ::bird2::config::variable{
#      bird6_variable:
#        scope     => 'ipv6',
#        replace   => false,
#        file_name => 'anycast-prefixes',
#        value     => [ '2001:db8::1/128', ];
#    }
#  }
#
#
# === Authors
#
# Pavlos Parissis <pavlos.parissis@gmail.com>
#
# === Copyright
#
# Copyright 2016 Pavlos Parissis, unless otherwise noted.
#
class anycast_healthchecker (
  $bird_conf             = $::anycast_healthchecker::params::bird_conf,
  $bird6_conf            = $::anycast_healthchecker::params::bird6_conf,
  $bird_variable         = $::anycast_healthchecker::params::bird_variable,
  $bird6_variable        = $::anycast_healthchecker::params::bird6_variable,
  $bird_reconfigure_cmd  = $::anycast_healthchecker::params::bird_reconfigure_cmd,
  $bird6_reconfigure_cmd = $::anycast_healthchecker::params::bird6_reconfigure_cmd,
  $bird_keep_changes     = $::anycast_healthchecker::params::bird_keep_changes,
  $bird6_keep_changes    = $::anycast_healthchecker::params::bird6_keep_changes,
  $bird_changes_counter  = $::anycast_healthchecker::params::bird_changes_counter,
  $bird6_changes_counter = $::anycast_healthchecker::params::bird6_changes_counter,
  $configuration_dir     = $::anycast_healthchecker::params::configuration_dir,
  $configuration_file    = $::anycast_healthchecker::params::configuration_file,
  $dummy_ip_prefix       = $::anycast_healthchecker::params::dummy_ip_prefix,
  $dummy_ip6_prefix      = $::anycast_healthchecker::params::dummy_ip6_prefix,
  $group                 = $::anycast_healthchecker::params::group,
  $http_server           = $::anycast_healthchecker::params::http_server,
  $http_server_port      = $::anycast_healthchecker::params::http_server_port,
  $http_server_protocol  = $::anycast_healthchecker::params::http_server_protocol,
  $http_server_timeout   = $::anycast_healthchecker::params::http_server_timeout,
  $ipv4                  = $::anycast_healthchecker::params::ipv4,
  $ipv6                  = $::anycast_healthchecker::params::ipv6,
  $json_logging          = $::anycast_healthchecker::params::json_logging,
  $log_level             = $::anycast_healthchecker::params::log_level,
  $log_maxbytes          = $::anycast_healthchecker::params::log_maxbytes,
  $log_backups           = $::anycast_healthchecker::params::log_backups,
  $log_dir               = $::anycast_healthchecker::params::log_dir,
  $log_file              = $::anycast_healthchecker::params::log_file,
  $motd_ensure           = $::anycast_healthchecker::params::motd_ensure,
  $package_name          = $::anycast_healthchecker::params::package_name,
  $package_version       = $::anycast_healthchecker::params::package_version,
  $pid_dir               = $::anycast_healthchecker::params::pid_dir,
  $pidfile               = $::anycast_healthchecker::params::pidfile,
  $purge_directory       = $::anycast_healthchecker::params::purge_directory,
  $purge_ip_prefixes     = $::anycast_healthchecker::params::purge_ip_prefixes,
  $service_enable        = $::anycast_healthchecker::params::service_enable,
  $service_ensure        = $::anycast_healthchecker::params::service_ensure,
  $service_name          = $::anycast_healthchecker::params::service_name,
  $stderr_file           = $::anycast_healthchecker::params::stderr_file,
  $stdout_file           = $::anycast_healthchecker::params::stdout_file,
  $user                  = $::anycast_healthchecker::params::user,
  $var_lib_dir           = $::anycast_healthchecker::params::var_lib_dir,
  $var_lib_dir6          = $::anycast_healthchecker::params::var_lib_dir6,
) inherits anycast_healthchecker::params {


  contain '::anycast_healthchecker::install'
  contain '::anycast_healthchecker::config'
  contain '::anycast_healthchecker::service'
  contain '::anycast_healthchecker::sudo_access'
  contain '::anycast_healthchecker::motd'

  Class['::anycast_healthchecker::install']     ~>
  Class['::anycast_healthchecker::config']      ~>
  Class['::anycast_healthchecker::service']     ->
  Class['::anycast_healthchecker::sudo_access'] ->
  Class['::anycast_healthchecker::motd']

}
