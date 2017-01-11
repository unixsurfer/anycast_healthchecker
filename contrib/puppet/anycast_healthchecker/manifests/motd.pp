# == Class: anycast_healthchecker::motd
#
# This class installs a motd message.
#
class anycast_healthchecker::motd {
  assert_private()
  $motd_text = [
    "Anycast-healthchecker runs here",
    "- Configuration files: $::anycast_healthchecker::configuration_dir/",
    "- Log files: $::anycast_healthchecker::log_dir/",
  ]
  motd::fragment {
    "20-motd-$::anycast_healthchecker::service_name":
      ensure  =>  $::anycast_healthchecker::motd_ensure,
      content => template('anycast_healthchecker/motd.erb');
  }
}
