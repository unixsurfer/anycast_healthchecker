# == Class: anycast_healthchecker::check
#
# A defined type class to configure healthchecker for monitoring a anycasted
# service. It produces a json configuration file which is parsed by healtchecker
# daemon.

# === Parameters:
#
# [*check_cmd*] <string>               - Full path of the command to run for
#                                        healthchecking the service.
#
# [*check_interval*] <number>          - Interval in secords between checks.
#
# [*check_timeout*] <number>           - Maximum time in seconds to wait for
#                                        a check to finish.
#
# [*check_rise*] <number>              - Number of consecutive successful checks
#                                        to consider the service healhty.
#
# [*check_fail*] <number>              - Number of consecutive unsuccessful
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
# [*ip_check_disabled] <boolean>       - true disables the assignment check of
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
  $check_cmd         = '/bin/false',
  $check_interval    = 10,
  $check_timeout     = 5,
  $check_rise        = 2,
  $check_fail        = 2,
  $check_disabled    = false,
  $on_disabled       = "withdraw",
  $ip_check_disabled = false,
  $ip_prefix,
  ) {

  if ! is_float($check_interval) {
    fail("anycast_healthchecker::check::${name} check_interval must be an integer or float")
  }
  if $check_interval < 0 {
    fail("anycast_healthchecker::check::${name} check_interval must be higher than zero")
  }
  if ! is_float($check_timeout) {
    fail("anycast_healthchecker::check::${name} check_timeout must be an integer or float")
  }
  if ! is_integer($check_rise) {
    fail("anycast_healthchecker::check::${name} check_rise must be an integer")
  }
  if $check_rise < 1 {
    fail("anycast_healthchecker::check::${name} check_rise must be higher than zero")
  }
  if ! is_integer($check_fail) {
    fail("anycast_healthchecker::check::${name} check_fail must be an integer")
  }
  if $check_fail < 1 {
    fail("anycast_healthchecker::check::${name} check_fail must be higher than zero")
  }
  validate_bool($check_disabled)
  validate_re($on_disabled, '^withdraw$|^advertise$')
  validate_bool($ip_check_disabled)


  $python_ver = regsubst($::anycast_healthchecker::package_name, '^blue-python(\d)(\d)-.*', '\1.\2')
  $_cmd = "/opt/blue-python/${python_ver}/bin/anycast-healthchecker"
  file {
    "$::anycast_healthchecker::configuration_dir/${name}.conf":
      mode     => '0444',
      owner    => root,
      group    => root,
      notify   => Service[$::anycast_healthchecker::service_name],
      validate_cmd => "su -s /bin/bash - $::anycast_healthchecker::user -c \'${_cmd} -c -F %\'",
      content  => template('anycast_healthchecker/check.conf.erb');
  }
}
