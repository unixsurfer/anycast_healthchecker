# == Class: anycast_healthchecker::sudo_access
#
# This class configures sudo access for healthchecker account
#
class anycast_healthchecker::sudo_access {
  assert_private()
  sudo::access{
    $::anycast_healthchecker::user:
      commands => [
        '/usr/sbin/birdcl configure',
        '/usr/sbin/birdcl6 configure',
        '/usr/sbin/birdc configure',
        '/usr/sbin/birdc6 configure',
        '/usr/local/bin/devkvmpuppet_anycast_healthchecker.sh',
        '/usr/local/bin/puppet_anycast_healthchecker.sh',
        '/usr/local/bin/puppetdb_anycast_healthchecker.sh',
      ];
    'nagios-anycast':
      group => 'nagios',
      commands => [
        '/usr/lib64/nagios/plugins/check_anycast_healthchecker.py',
        '/usr/lib64/nagios/plugins/check_anycast_healthchecker_threads.py',
      ];
  }
}
