# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
"""A healthchecker for Anycasted services."""
__title__ = 'anycast_healthchecker'
__author__ = 'Pavlos Parissis'
__license__ = 'Apache 2.0'
__version__ = '0.8.0'
__copyright__ = 'Copyright 2015-2017 Pavlos Parissis'

PROGRAM_NAME = __title__.replace('_', '-')

DEFAULT_OPTIONS = {
    'DEFAULT': {
        'interface': 'lo',
        'check_interval': '10',
        'check_timeout': '2',
        'check_rise': '2',
        'check_fail': '2',
        'check_disabled': 'true',
        'on_disabled': 'withdraw',
        'ip_check_disabled': 'false',
    },
    'daemon': {
        'ipv4': 'true',
        'ipv6': 'false',
        'bird_conf': '/var/lib/anycast-healthchecker/anycast-prefixes.conf',
        'bird6_conf': '/var/lib/anycast-healthchecker/6/anycast-prefixes.conf',
        'bird_variable': 'ACAST_PS_ADVERTISE',
        'bird6_variable': 'ACAST6_PS_ADVERTISE',
        'bird_reconfigure_cmd': 'sudo /usr/sbin/birdc configure',
        'bird6_reconfigure_cmd': 'sudo /usr/sbin/birdc6 configure',
        'dummy_ip_prefix': '10.189.200.255/32',
        'dummy_ip6_prefix': '2001:db8::1/128',
        'bird_keep_changes': 'false',
        'bird6_keep_changes': 'false',
        'bird_changes_counter': '128',
        'bird6_changes_counter': '128',
        'purge_ip_prefixes': 'false',
        'pidfile': '/var/run/anycast-healthchecker/anycast-healthchecker.pid',
        'loglevel': 'debug',
        'log_server_port': '514',
        'json_stdout': 'false',
        'json_log_file': 'false',
        'json_log_server': 'false',
        'log_maxbytes': '104857600',
        'log_backups': '8',
    }
}
