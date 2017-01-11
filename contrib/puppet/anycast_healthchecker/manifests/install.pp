# == Class: anycast_healthchecker::install
#
# This class manages anycast_healthchecker parameters
#
class anycast_healthchecker::install {
  assert_private()
  package {
    $::anycast_healthchecker::package_name:
      ensure => $::anycast_healthchecker::package_version;
  }
}
