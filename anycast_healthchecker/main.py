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
from lockfile.pidlockfile import PIDLockFile
from docopt import docopt

from anycast_healthchecker import DEFAULT_OPTIONS
from anycast_healthchecker import healthchecker
from anycast_healthchecker import lib
from anycast_healthchecker import __version__ as version
from anycast_healthchecker.utils import (load_configuration, running,
                                         ip_prefixes_check)


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

    config_file = args['--file']
    config_dir = args['--dir']
    try:
        config = load_configuration(config_file, config_dir)
    except ValueError as exc:
        sys.exit('Invalid configuration: ' + str(exc))

    if args['--check']:
        print("OK")
        sys.exit(0)

    if args['--print-conf']:
        for section in config:
            print("[{}]".format(section))
            for key, value in config[section].items():
                print("{k} = {v}".format(k=key, v=value))
            print()
        sys.exit(0)


    # Catch already running process and clean up stale pid file.
    pidfile = config.get('daemon', 'pidfile')
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
    num_level = getattr(
        logging,
        config.get('daemon', 'loglevel').upper(),  # pylint: disable=no-member
        None
    )

    # Set up loggers for stdout, stderr and daemon stream
    log = lib.LoggerExt(
        'daemon',
        config.get('daemon', 'log_file'),
        log_level=num_level,
        maxbytes=config.getint('daemon', 'log_maxbytes'),
        backupcount=config.getint('daemon', 'log_backups')
    )
    if config.getboolean('daemon', 'json_logging', fallback=False):
        log.add_central_logging(
            server=config.get('daemon', 'http_server'),
            timeout=config.getfloat('daemon', 'http_server_timeout'),
            protocol=config.get('daemon', 'http_server_protocol'),
            port=config.get('daemon', 'http_server_port')
        )
    stdout_log = lib.LoggerExt(
        'stdout',
        config.get('daemon', 'stdout_file'),
        log_level=num_level)

    stderrformat = ('%(asctime)s [%(process)d] line:%(lineno)d '
                    'func:%(funcName)s %(levelname)-8s %(threadName)-32s '
                    '%(message)s')
    stderr_log = lib.LoggerExt(
        'stderr',
        config.get('daemon', 'stderr_file'),
        log_level=num_level,
        log_format=stderrformat)

    if config.getboolean('daemon', 'json_logging', fallback=False):
        stderr_log.add_central_logging(
            server=config.get('daemon', 'http_server'),
            timeout=config.getfloat('daemon', 'http_server_timeout'),
            protocol=config.get('daemon', 'http_server_protocol'),
            port=config.get('daemon', 'http_server_port')
        )

    # Perform a sanity check on IP-Prefixes
    ip_prefixes_check(log, config)

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
    pid_lockfile = PIDLockFile(config.get('daemon', 'pidfile'))
    context.pidfile = pid_lockfile

    # Create our master process.
    checker = healthchecker.HealthChecker(
        log,
        config,
        config.get('daemon', 'bird_conf'),
        config.get('daemon', 'bird_variable'),
        config.get('daemon', 'dummy_ip_prefix'))

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
