# == Class: anycast_healthchecker::check
#
# A defined type class to configure healthchecker for monitoring a anycasted
# service. It produces a json configuration file which is parsed by healtchecker
# daemon.

# === Parameters:
#
# [*interface*] <string>               - Interface that the service IP resides on.
#                                        Defaults to 'lo'.
#
# [*check_cmd*] <string>               - Full path of the command to run for
#                                        healthchecking the service.
#
# [*check_interval*] <number>          - Interval in secords between checks.
#
# [*check_timeout*] <number>           - Maximum time in seconds to wait for
#                                        a check to finish.
#
# [*check_rise*] <integer>             - Number of consecutive successful checks
#                                        to consider the service healhty.
#
# [*check_fail*] <integer>             - Number of consecutive unsuccessful
#                                        checks to consider the service dead.
#
# [*check_disabled*] <boolean>         - Disables check for service.
#
# [*on_disabled*] <withdraw|advertise> - Action to take when check is disabled
#                                        -- withdraw  => withdraw the ip_prefix
#                                        -- advertise => advertise the ip_prefix
# [*ip_prefix*]  <IP_PREFIX>           - The ip_prefix associated with the
#                                        service in a IP address/prefix_len format.
#
# [*ip_check_disabled*] <boolean>      - true disables the assignment check of
#                                        ip_prefix to the interface set in interface,
#                                        false enables it.
#
# This class requires the following external variables
#
# This class requires the following templates
#
# anycast/healthcheck.json.erb
#
# === Actions:
#
# -- Perform sanity checks for all given parameters
#
# === Requires:
#
#     anycast::healthcheck class
# === Sample Usage:
#
#     anycast_healthchecker::check {
#       'for.bar.com':
#         ip_prefix => '10.189.200.1/32',
#         check_cmd => '/usr/bin/curl -o /dev/null  http://10.189.200.1/';
#     }
#
# === Authors
#
# Pavlos Parissis <pavlos.parissis@gmail.com>
#
define anycast_healthchecker::check (
  Variant[Stdlib::IP::Address::V4::CIDR,
          Stdlib::IP::Address::V6::CIDR] $ip_prefix,
  String[1]                              $interface         = 'lo',
  String[1]                              $check_cmd         = '/bin/false',
  Numeric                                $check_interval    = 10,
  Numeric                                $check_timeout     = 5,
  Integer[1]                             $check_rise        = 2,
  Integer[1]                             $check_fail        = 2,
  Boolean                                $check_disabled    = false,
  Enum['withdraw', 'advertise']          $on_disabled       = 'withdraw',
  Boolean                                $ip_check_disabled = false,
) {

  if $check_interval < 0 {
    fail("anycast_healthchecker::check::${name} check_interval must be higher than zero")
  }
  if $check_timeout < 0 {
    fail("anycast_healthchecker::check::${name} check_timeout must be higher than zero")
  }

  $python_ver = regsubst($::anycast_healthchecker::package_name, '^blue-python(\d)(\d)-.*', '\1.\2')
  $_cmd = "/opt/blue-python/${python_ver}/bin/anycast-healthchecker"
  file {
    "${::anycast_healthchecker::configuration_dir}/${name}.conf":
      mode         => '0444',
      owner        => root,
      group        => root,
      notify       => Service[$::anycast_healthchecker::service_name],
      validate_cmd => "su -s /bin/bash - ${::anycast_healthchecker::user} -c \'${_cmd} -c -F %\'",
      content      => template('anycast_healthchecker/check.conf.erb');
  }
}
