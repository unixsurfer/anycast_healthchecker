# == Class: anycast_healthchecker::config
#
# This class configures anycast-healthchecker
#
class anycast_healthchecker::config {
  assert_private()
  file {
    $::anycast_healthchecker::log_dir:
      ensure  => directory,
      owner   => $::anycast_healthchecker::user,
      group   => $::anycast_healthchecker::group,
      mode    => '0755';
  }
  file {
    $::anycast_healthchecker::var_lib_dir:
      ensure  => directory,
      owner   => $::anycast_healthchecker::user,
      group   => $::anycast_healthchecker::group,
      mode    => '0755';
  }

  $var_lib_dir6_ensure = $::anycast_healthchecker::ipv6 ? {
    true  => directory,
    false => absent,
  }
  file {
    $::anycast_healthchecker::var_lib_dir6:
      ensure => $var_lib_dir6_ensure,
      owner  => $::anycast_healthchecker::user,
      group  => $::anycast_healthchecker::group,
      force  => true,
      mode   => '0755';
  }
  file {
    $::anycast_healthchecker::pid_dir:
      ensure  => directory,
      owner   => $::anycast_healthchecker::user,
      group   => $::anycast_healthchecker::group,
      mode    => '0755';
  }
  file {
    $::anycast_healthchecker::configuration_dir:
      ensure  => directory,
      purge   => $::anycast_healthchecker::purge_directory,
      recurse => $::anycast_healthchecker::purge_directory,
      owner   => root,
      group   => root,
      mode    => '0755';
  }
  $python_ver = regsubst($::anycast_healthchecker::package_name, '^blue-python(\d)(\d)-.*', '\1.\2')
  $check_cmd = "/opt/blue-python/${python_ver}/bin/anycast-healthchecker"
  file {
    $::anycast_healthchecker::configuration_file:
      mode         => '0444',
      owner        => root,
      group        => root,
      content      => template('anycast_healthchecker/anycast-healthchecker.conf.erb'),
      validate_cmd => "su -s /bin/bash - $::anycast_healthchecker::user -c \'${check_cmd} -c -f %\'",
      require      => File[$::anycast_healthchecker::configuration_dir];
  }
  file {
    'sysconfig':
      path    => '/etc/sysconfig/anycast-healthchecker',
      mode    => '0444',
      owner   => root,
      group   => root,
      source  => 'puppet:///modules/anycast_healthchecker/anycast-healthchecker.sysconfig';
  }
  $tmpfiles_config_ensure = $::facts['lsbmajdistrelease'] ? {
    6       => absent,  # RedHat 5 isn't supported anymore
    default => file,
  }
  file {
    '/usr/lib/tmpfiles.d/anycast-healthchecker.conf':
      ensure  =>  $tmpfiles_config_ensure,
      owner   => root,
      group   => root,
      mode    => '0444',
      content => template('anycast_healthchecker/tmpfiles.conf.erb');
  }
}
