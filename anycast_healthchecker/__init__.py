# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
"""
anycast healthchecker daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A healthchecker for Anycasted services.

"""
__title__ = 'anycast_healthchecker'
__author__ = 'Pavlos Parissis'
__license__ = 'Apache 2.0'
__version__ = '0.6.2'
__copyright__ = 'Copyright 2015-2016 Pavlos Parissis'

DEFAULT_OPTIONS = {
    'DEFAULT': {
        'interface': 'lo',
        'check_interval': '10',
        'check_timeout': '2',
        'check_rise': '2',
        'check_fail': '2',
        'check_disabled': 'true',
        'on_disable': 'withdraw',
        'ip_check_disabled': 'false',
        'purge_ip_prefixes': 'false',
    },
    'daemon': {
        'pidfile': '/var/run/anycast-healthchecker/anycast-healthchecker.pid',
        'bird_conf': '/etc/bird.d/anycast-prefixes.conf',
        'bird_variable': 'ACAST_PS_ADVERTISE',
        'loglevel': 'debug',
        'log_maxbytes': '104857600',
        'log_backups': '8',
        'log_file': '/var/log/anycast-healthchecker/anycast-healthchecker.log',
        'stderr_file': '/var/log/anycast-healthchecker/stderr.log',
        'stdout_file': '/var/log/anycast-healthchecker/stdout.log',
        'dummy_ip_prefix': '10.189.200.255/32',
        'bird_reconfigure_cmd': 'sudo /usr/sbin/birdc configure',
    }
}
