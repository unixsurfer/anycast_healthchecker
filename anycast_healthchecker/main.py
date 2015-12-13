#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# pylint: disable=too-many-arguments
# pylint: disable=too-many-statements
# pylint: disable=superfluous-parens
#
"""A simple healthchecker for Anycasted services.

Usage:
    anycast-healthchecker [-f <file> -d <directory> -c ] [-p | -P]

Options:
    -f, --file <file>  configuration file with settings for the daemon
                       [default: /etc/anycast-healthchecker.conf]
    -d, --dir <dir>    directory with configuration files for service checks
                       [default: /etc/anycast-healthchecker.d]
    -c, --check        perform a sanity check on configuration
    -p, --print        show default settings for daemon and service checks
    -P, --print-conf   show configuration
    -v, --version      show version
    -h, --help         show this screen
"""
import os
import sys
import signal
import logging
import configparser
import glob
import copy
from lockfile.pidlockfile import PIDLockFile
from docopt import docopt

from anycast_healthchecker import healthchecker
from anycast_healthchecker import lib
from anycast_healthchecker import __version__ as version
from anycast_healthchecker.utils import configuration_check, running

DEFAULT_OPTIONS = {
    'DEFAULT': {
        'interface': 'lo',
        'check_interval': '10',
        'check_timeout': '2',
        'check_rise': '2',
        'check_fail': '2',
        'check_disabled': 'true',
        'on_disable': 'withdraw',
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


def main():
    """Parse CLI and starts daemon."""

    args = docopt(__doc__, version=version)
    if args['--print']:
        for section in DEFAULT_OPTIONS:
            print("[{}]".format(section))
            for key, value in DEFAULT_OPTIONS[section].items():
                print("{k} = {v}".format(k=key, v=value))
            print()
        sys.exit(0)

    # Parse configuration.
    defaults = copy.copy(DEFAULT_OPTIONS['DEFAULT'])
    daemon_defaults = {'daemon': copy.copy(DEFAULT_OPTIONS['daemon'])}
    config = configparser.ConfigParser(defaults=defaults)
    config.read_dict(daemon_defaults)
    config_files = [args['--file']]
    config_files.extend(glob.glob(os.path.join(args['--dir'], '*.conf')))
    config.read(config_files)

    if args['--print-conf']:
        for section in config:
            print("[{}]".format(section))
            for key, value in config[section].items():
                print("{k} = {v}".format(k=key, v=value))
            print()
        sys.exit(0)

    # Perform a sanity check on the configuration
    configuration_check(config)
    if args['--check']:
        print("OK")
        sys.exit(0)

    # Catch already running process and clean up stale pid file.
    pidfile = config['daemon']['pidfile']
    if os.path.exists(pidfile):
        pid = open(pidfile).read().rstrip()
        try:
            pid = int(pid)
        except ValueError:
            print("Cleaning stale pid file with invalid data:{}".format(pid))
            os.unlink(pidfile)
        else:
            if running(pid):
                sys.exit("Process {} is already running".format(pid))
            else:
                print("Cleaning stale pid file with pid:{}".format(pid))
                os.unlink(pidfile)

    # Map log level to numeric which can be accepted by loggers.
    num_level = getattr(logging, config['daemon']['loglevel'].upper(), None)

    # Set up loggers for stdout, stderr and daemon stream
    log = lib.LoggerExt(
        'daemon',
        config['daemon']['log_file'],
        log_level=num_level,
        maxbytes=config.getint('daemon', 'log_maxbytes'),
        backupcount=config.getint('daemon', 'log_backups')
    )
    if config.getboolean('daemon', 'json_logging', fallback=False):
        log.add_central_logging(
            server=config['daemon']['http_server'],
            timeout=config.getfloat('daemon', 'http_server_timeout'),
            protocol=config['daemon']['http_server_protocol'],
            port=config['daemon']['http_server_port'])
    stdout_log = lib.LoggerExt(
        'stdout',
        config['daemon']['stdout_file'],
        log_level=num_level)

    stderrformat = ('%(asctime)s [%(process)d] line:%(lineno)d '
                    'func:%(funcName)s %(levelname)-8s %(threadName)-32s '
                    '%(message)s')
    stderr_log = lib.LoggerExt(
        'stderr',
        config['daemon']['stderr_file'],
        log_level=num_level,
        log_format=stderrformat)

    if config.getboolean('daemon', 'json_logging', fallback=False):
        stderr_log.add_central_logging(
            server=config['daemon']['http_server'],
            timeout=config.getfloat('daemon', 'http_server_timeout'),
            protocol=config['daemon']['http_server_protocol'],
            port=config['daemon']['http_server_port'])

    # Make some noise.
    log.debug('Before we are daemonized')
    stdout_log.debug('before we are daemonized')
    stderr_log.debug('before we are daemonized')

    # Get and set the DaemonContext.
    context = lib.LoggingDaemonContext()
    context.loggers_preserve = [log]
    context.stdout_logger = stdout_log
    context.stderr_logger = stderr_log

    # Set pidfile for DaemonContext
    pid_lockfile = PIDLockFile(config['daemon']['pidfile'])
    context.pidfile = pid_lockfile

    # Create our master process.
    checker = healthchecker.HealthChecker(
        log,
        config,
        config['daemon']['bird_conf'],
        config['daemon']['bird_variable'],
        config['daemon']['dummy_ip_prefix'])

    # Set signal mapping to catch singals and act accordingly.
    context.signal_map = {
        signal.SIGHUP: checker.catch_signal,
        signal.SIGTERM: checker.catch_signal,
    }

    # OK boy go and daemonize yourself.
    with context:
        log.info("starting daemon {}".format(version))
        checker.run()
# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
