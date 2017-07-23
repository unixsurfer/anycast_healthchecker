#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
"""A simple healthchecker for Anycasted services.

Usage:
    anycast-healthchecker [ -f <file> -c -p -P ] [ -d <directory> | -F <file> ]

Options:
    -f, --file=<file>          read settings from <file>
                               [default: /etc/anycast-healthchecker.conf]
    -d, --dir=<dir>            read settings for service checks from files
                               under <dir> directory
                               [default: /etc/anycast-healthchecker.d]
    -F, --service-file=<file>  read <file> for settings of a single service
                               check
    -c, --check                perform a sanity check on configuration
    -p, --print                show default settings for anycast-healthchecker
                               and service checks
    -P, --print-conf           show running configuration with default settings
                               applied
    -v, --version              show version
    -h, --help                 show this screen
"""
from functools import partial
import socket
import signal
import sys
from docopt import docopt

from anycast_healthchecker import (DEFAULT_OPTIONS, PROGRAM_NAME, __version__,
                                   healthchecker)
from anycast_healthchecker.utils import (load_configuration, shutdown,
                                         ip_prefixes_sanity_check,
                                         update_pidfile, setup_logger)

LOCK_SOCKET = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)


def main():
    """Parse CLI and starts main program."""
    args = docopt(__doc__, version=__version__)
    if args['--print']:
        for section in DEFAULT_OPTIONS:
            print("[{}]".format(section))
            for key, value in DEFAULT_OPTIONS[section].items():
                print("{k} = {v}".format(k=key, v=value))
            print()
        sys.exit(0)

    try:
        config, bird_configuration = load_configuration(args['--file'],
                                                        args['--dir'],
                                                        args['--service-file'])
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

    try:
        LOCK_SOCKET.bind('\0' + "{}".format(PROGRAM_NAME))
    except socket.error as exc:
        sys.exit("failed to acquire a lock by creating an abstract namespace"
                 " socket: {}".format(exc))
    else:
        print("acquired a lock by creating an abstract namespace socket")

    # Clean old pidfile, if it exists, and write PID to it.
    pidfile = config.get('daemon', 'pidfile')
    update_pidfile(pidfile)

    # Register our shutdown handler to various termination signals.
    shutdown_handler = partial(shutdown, pidfile)
    signal.signal(signal.SIGHUP, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGABRT, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    # Set up loggers.
    logger = setup_logger(config)

    # Perform a sanity check on IP-Prefixes
    ip_prefixes_sanity_check(config, bird_configuration)

    # Create our master process.
    checker = healthchecker.HealthChecker(config, bird_configuration)
    logger.info("starting %s %s version", PROGRAM_NAME, __version__)
    checker.run()


# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
