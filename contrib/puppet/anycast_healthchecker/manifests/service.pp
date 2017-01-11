# == Class: anycast_healthchecker::service
#
# This class manages anycast-healthchecker service
#
class anycast_healthchecker::service {
  assert_private()
  service {
    $::anycast_healthchecker::service_name:
      ensure => $::anycast_healthchecker::service_ensure,
      enable => $::anycast_healthchecker::service_enable;
  }
}
