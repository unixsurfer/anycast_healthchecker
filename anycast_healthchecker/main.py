#!/usr/local/bin/blue-python3.4
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# File name: anycast_healthchecker.py
#
# Creation date: 21-10-2014
#
# Created by: Pavlos Parissis <pavlos.parissis@booking.com>
#
# pylint: disable=too-many-arguments
# pylint: disable=too-many-statements
# pylint: disable=superfluous-parens
#
import os
import sys
import signal
import logging
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from lockfile.pidlockfile import PIDLockFile

from anycast_healthchecker import healthchecker
from anycast_healthchecker import lib

NAME_OF_CONSTANT = 'ACAST_PS_ADVERTISE'


def main():
    """This is a main function

    Parses CLI arguments.
    Prevents running if another process is already running.
    Sets a PID lock file.
    Sets up loggers.
    Instantiate daemon.DaemonContext object.
    Instantiate a healtherchecker object which will be daemonized.
    Sets up signal catcher on daemonized object.
    Last but not least, daemonize this program.

    """
    # Set and parse arguments.
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="""
        A Healthchecker for Anycasted services. Triggers updates to BIRD
        daemon based on the result of a check. It modifies a file which
        defines a constant array which is used by BIRD daemon in a filter
        function. It should be combined with BIRD daemon as by itself
        does nothing useful.
        """)
    parser.add_argument(
        '-c', '--config-dir',
        dest='cfg_dir',
        help='Configuration directory',
        default='/etc/anycast-servicecheck.d')
    parser.add_argument(
        '-p', '--pidfile',
        help='Pid file',
        default='/var/run/anycast-healthchecker/anycast-healthchecker.pid')
    parser.add_argument(
        '-l', '--log-level', dest='loglevel',
        help='Log level',
        choices=[
            'debug',
            'info',
            'warning',
            'error',
            'critical'
        ],
        default='debug')
    parser.add_argument(
        '--log-maxbytes', '-lm', dest='log_maxbytes',
        default=104857600,
        type=int,
        help='Maximum size of log file')
    parser.add_argument(
        '--log-backupcount', '-lb', dest='log_backupcount',
        default=8,
        type=int,
        help='Number of backup file to keep')
    parser.add_argument(
        '--bird-conf', '-b', dest='bird_conf_file',
        default='/etc/bird.d/anycast-prefixes.conf',
        help='Bird config file')
    parser.add_argument(
        '--bird-constant-name', '-g', dest='bird_constant_name',
        default='ACAST_PS_ADVERTISE',
        help='Name of the constant used in Bird config file')
    parser.add_argument(
        '--log-file', '-f', dest='log_file',
        default='/var/log/anycast-healthchecker/anycast-healthchecker.log',
        help='Log file')
    parser.add_argument(
        '--stderr-file', '-e', dest='stderr_log_file',
        default='/var/log/anycast-healthchecker/stderr.log',
        help='Error log file')
    parser.add_argument(
        '--stdout-file', '-s', dest='stdout_log_file',
        default='/var/log/anycast-healthchecker/stdout.log',
        help='Standard output log file')
    args = parser.parse_args()

    # Catch already running process and clean up stale pid file.
    if os.path.exists(args.pidfile):
        pid = int(open(args.pidfile).read().rstrip())
        if lib.running(pid):
            print("Process {} is already running".format(pid))
            sys.exit(1)
        else:
            print("Cleaning stale pid file, past pid {}".format(pid))
            os.unlink(args.pidfile)

    # Get a PID lock file.
    pid_lockfile = PIDLockFile(args.pidfile)
    # Map log level to numeric which can be accepted by loggers.
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(args.loglevel))

    # Set up loggers for stdout, stderr and daemon stream
    log = lib.get_file_logger(
        'daemon',
        args.log_file,
        log_level=numeric_level,
        maxbytes=args.log_maxbytes,
        backupcount=args.log_backupcount)
    stdout_log = lib.get_file_logger(
        'stdout',
        args.stdout_log_file,
        log_level=numeric_level)

    stderrformat = ('%(asctime)s [%(process)d] line:%(lineno)d '
                    'func:%(funcName)s %(levelname)-8s %(threadName)-32s '
                    '%(message)s')
    stderr_log = lib.get_file_logger(
        'stderr',
        args.stderr_log_file,
        log_level=numeric_level,
        log_format=stderrformat)

    # Make some noise.
    log.debug('Before we are daemonized')
    stdout_log.debug('Before we are daemonized')
    stderr_log.debug('Before we are daemonized')

    # Get and set the DaemonContext.
    context = lib.LoggingDaemonContext()
    context.loggers_preserve = [log]
    context.stdout_logger = stdout_log
    context.stderr_logger = stderr_log

    # Set pidfile for DaemonContext
    context.pidfile = pid_lockfile

    # Create our master process.
    checker = healthchecker.HealthChecker(
        log,
        args.cfg_dir,
        args.bird_conf_file,
        args.bird_constant_name)

    # Set signal mapping to catch singals and act accordingly.
    context.signal_map = {
        signal.SIGHUP: checker.catch_signal,
        signal.SIGTERM: checker.catch_signal,
    }

    # OK boy go and daemonize yourself.
    with context:
        log.info('Running as a daemon')
        stdout_log.debug('Running as a daemon')
        stderr_log.debug('Running as a daemon')
        checker.run()
# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
