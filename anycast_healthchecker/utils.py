# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# pylint: disable=superfluous-parens
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
# pylint: disable=too-few-public-methods
"""
anycast_healthchecker.utils
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides utility functions and classes that are used within
anycast_healthchecker.
"""

import re
import os
import sys
import subprocess
import logging
import configparser
import shlex


OPTIONS_TYPE = {
    'check_cmd': 'get',
    'check_interval': 'getint',
    'check_timeout': 'getint',
    'check_rise': 'getint',
    'check_fail': 'getint',
    'check_disabled': 'getboolean',
    'on_disabled': 'get',
    'ip_prefix': 'get',
    'interface': 'get',
}


def valid_ip_prefix(ip_prefix):
    """Returns true if input is a valid IP Prefix otherwhise False."""

    pattern = re.compile(r'''
        ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}  # 1-3 octets
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)            # 4th octet
        (\/([0-9]|[1-2][0-9]|3[0-2]))$                      # prefixlen
        ''', re.VERBOSE)

    return pattern.match(ip_prefix)


def touch(file_path):
    """Touches a file in the same way as touch tool does"""

    try:
        with open(file_path, 'a') as file_hanle:
            os.utime(file_path, None)
    except OSError as error:
        print("Failed to touch file with error:{err}".format(err=error))
        return False
    else:
        file_hanle.close()
        return True


def get_ip_prefixes(config, services):
    """Builds a set of IP prefixes found in configuration files.

    Arguments:
        config (obg): A configparser object which holds our configuration.
        services (list): A list of section names which are the name of the
        service checks.

    Returns:
        A set of IP prefixes.
    """

    ip_prefixes = set()

    for service in services:
        ip_prefixes.add(config[service]['ip_prefix'])

    return ip_prefixes


def service_configuration_check(config, services):
    """Performs a sanity check on options for each service check

    Arguments:
        config (obj): A configparser object which holds our configuration.
        services (list): A list of section names which are the name of the
        services to run checks.

    Returns:
        None if all sanity checks on configuration are successfully passed
        otherwise exits main program
    """
    for service in services:
        for option, getter in OPTIONS_TYPE.items():
            try:
                getattr(config, getter)(service, option)
            except configparser.Error as error:
                sys.exit(str(error))
            except ValueError as error:
                sys.exit("invalid data for '{opt}' option in service check "
                         "{name}: {err}".format(opt=option, name=service,
                                                err=error))

        if (config[service]['on_disabled'] != 'withdraw' and
                config[service]['on_disabled'] != 'advertise'):
            sys.exit("'on_disable' option has invalid value ({val}) for "
                     "service check {name} should be either 'withdraw' or "
                     "'advertise'".format(name=service,
                                          val=config[service]['on_disabled']))

        # check if it is a valid IP
        if not valid_ip_prefix(config[service]['ip_prefix']):
            sys.exit("invalid value ({val}) for 'ip_prefix' option in service "
                     "check {name}. It should be an IP PREFIX in form of "
                     "ip/prefixlen.".format(name=service,
                                            val=config[service]['ip_prefix']))

        cmd = shlex.split(config[service]['check_cmd'])
        try:
            proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
            proc.kill()
        except (OSError, subprocess.SubprocessError) as error:
            sys.exit("failed to run check command '{cmd}' for service check "
                     "{name}: {err}".format(name=service,
                                            cmd=config[service]['check_cmd'],
                                            err=str(error)))


def ip_prefixes_without_config(ip_prefixes_in_bird, config, services):
    """Find IP prefixes in Bird configuration without a check.

    Arguments:
        ip_prefixes_in_bird (list): A list of IP prefixes configured in Bird.
        config (obg): A configparser object which holds our configuration.
        services (list): A list of section names which are the name of the
        service checks.

    Returns:
        A sequence (set) with IP prefixes without a check associated with them.
    """
    configured = get_ip_prefixes(config, services)
    # dummy_ip_prefix doesn't have a config by design
    configured.add(config['daemon']['dummy_ip_prefix'])

    return set(ip_prefixes_in_bird).difference(configured)


def ip_prefixes_check(config, services):
    """Reports issues with IP prefixes.

    - Report IP prefixes found in Bird configuration for which we don't have
    a service check associated with.
    - Report missing ``dummy_ip_prefix`` in Bird configuration

    Arguments:
        config (obg): A configparser object which holds our configuration.
        services (list): A list of section names which are the name of the
        service checks.
    """
    ip_prefixes_in_bird = get_ip_prefixes_from_bird(
        config['daemon']['bird_conf'])

    if not ip_prefixes_in_bird:
        print("Found zero IP prefixes in {}".format(
            config['daemon']['bird_conf']))
        return None

    notconfigured_ip_prefixes = ip_prefixes_without_config(ip_prefixes_in_bird,
                                                           config,
                                                           services)
    if notconfigured_ip_prefixes:
        print("Found IP prefixes {i} in {fh} without a check configured"
              .format(fh=config['daemon']['bird_conf'],
                      i=','.join(notconfigured_ip_prefixes)))

    if config['daemon']['dummy_ip_prefix'] not in ip_prefixes_in_bird:
        print("Dummy IP prefix ({ip}) is missing from bird configuration "
              "{fh}".format(ip=config['daemon']['dummy_ip_prefix'],
                            fh=config['daemon']['bird_conf']))


def configuration_check(config):
    """Perform a sanity check on configuration

    Arguments:
        config (obg): A configparser object which holds our configuration.

    Returns:
        None if all checks are successfully passed otherwise exits main
        program
    """
    num_level = getattr(logging, config['daemon']['loglevel'].upper(), None)
    if not isinstance(num_level, int):
        sys.exit('Invalid log level: {}'.format(config['daemon']['loglevel']))

    if not touch(config['daemon']['log_file']):
        sys.exit(1)
    if not touch(config['daemon']['stdout_file']):
        sys.exit(1)
    if not touch(config['daemon']['stderr_file']):
        sys.exit(1)
    if not valid_ip_prefix(config['daemon']['dummy_ip_prefix']):
        sys.exit("Invalid dummy IP prefix:{}".format(
            config['daemon']['dummy_ip_prefix']))

    services = config.sections()
    services.remove('daemon')
    if not services:
        sys.exit('No service checks are configured')

    service_configuration_check(config, services)
    ip_prefixes_check(config, services)


def running(processid):
    """Checks the validity of a process ID.

    Arguments:
        processid (int): Process ID number.

    Returns:
        True if process ID is found otherwise False.
    """
    try:
        # From kill(2)
        # If sig is 0 (the null signal), error checking is performed but no
        # signal is actually sent. The null signal can be used to check the
        # validity of pid
        os.kill(processid, 0)
    except OSError:
        return False

    return True


def get_ip_prefixes_from_bird(filename, die=True):
    """Builds a list of IP prefixes found in Bird configuration

    Arguments:
        filename(str): The absolute path of the Bird configuration file.

    Notes:
        It can only parse a file with the following format

            define ACAST_PS_ADVERTISE =
                [
                    10.189.200.155/32,
                    10.189.200.255/32
                ];

    Returns:
        A list of IP prefixes.
    """
    prefixes = []
    try:
        with open(filename, 'r') as bird_conf:
            lines = bird_conf.read()
    except OSError as error:
        if die:
            sys.exit(str(error))
        else:
            raise
    else:
        for line in lines.splitlines():
            line = line.strip(', ')
            if valid_ip_prefix(line):
                prefixes.append(line.rstrip(','))

    return prefixes


class BaseOperation(object):
    """Runs operation on a list


    Arguments:
        name(string): The name of the service for the given ip_prefix
        ip_prefix(string): The value to run the operation
        log(logger obj): A logger object to use for emitting messages
        extra(dictinary): A possible dictinary structure to pass further
    """
    def __init__(self, name, ip_prefix, log, **extra):
        self.name = name
        self.ip_prefix = ip_prefix
        self.log = log
        self.extra = extra


class AddOperation(BaseOperation):
    """Adds a value to a list"""
    def __str__(self):
        """Overwrite the behavior so the class

        A handy way to pass the instantiated object to a string formatter
        """
        return 'add to'

    def update(self, prefixes):
        """Add a value to the list

        Arguments:
            prefixes(list): A list to add the value
        """
        if self.ip_prefix not in prefixes:
            prefixes.append(self.ip_prefix)
            msg = ("announcing {i} for {n}".format(i=self.ip_prefix,
                                                   n=self.name))
            self.log.info(msg, **self.extra)
            return True

        return False


class DeleteOperation(BaseOperation):
    """Removes a value to a list"""
    def __str__(self):
        return 'delete from'

    def update(self, prefixes):
        """Remove a value to the list

        Arguments:
            prefixes(list): A list to remove the value
        """
        if self.ip_prefix in prefixes:
            prefixes.remove(self.ip_prefix)
            msg = "withdrawing {i} for {n}".format(i=self.ip_prefix,
                                                   n=self.name)
            self.log.info(msg, **self.extra)
            return True

        return False
