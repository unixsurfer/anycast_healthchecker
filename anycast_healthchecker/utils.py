# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# pylint: disable=superfluous-parens
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals

import re
import os
import json
import sys
import glob
import subprocess
import copy


OPTIONS_TYPE = {
    "name": str,
    "check_cmd": str,
    "check_interval": int,
    "check_timeout": int,
    "check_rise": int,
    "check_fail": int,
    "check_disabled": bool,
    "on_disabled": str,
    "ip_prefix": str
}


def valid_ip_prefix(ip_prefix):
    """Returns true if input is a valid IP Prefix otherwhise False."""

    pattern = re.compile(r'''
        ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}  # 1-3 octets
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)            # 4th octet
        (\/([0-9]|[1-2][0-9]|3[0-2]))$                      # prefixlen
        ''', re.VERBOSE)

    if pattern.match(ip_prefix):
        return True
    else:
        return False


def touch(file_path):
    """Touch a file in the same way as touch tool does"""

    try:
        with open(file_path, 'a') as fh:
            os.utime(file_path, None)
    except OSError as error:
        print("Failed to touch file with error:{err}".format(err=error))
        return False
    else:
        fh.close()
        return True


def get_config_files(cfg_dir):
    """Retrieves the absolute file path of configuration files.

    Returns:
        A list of absolute file paths.
    """
    file_names = []
    for name in glob.glob(os.path.join(cfg_dir, '*.json')):
        file_names.append(name)

    return file_names


def get_ip_prefixes(config):
    """Return a set of ip prefixes found in configuration files"""

    ip_prefixes = set()

    for data in config:
        ip_prefixes.add(config[data]['ip_prefix'])

    return ip_prefixes


def get_config(cfg_dir):
    """Parse a json files and return a dict structure"""
    files = []
    full_config = {}
    files = get_config_files(cfg_dir)
    if not files:
        sys.exit("No configuration was found in {}".format(cfg_dir))

    for filename in files:
        try:
            with open(filename, 'r') as conf:
                config_data = json.load(conf)
        except ValueError as error:
            sys.exit("{fh}: isn't a valid JSON file: {err}".format(
                fh=filename,
                err=str(error)))
        except OSError as error:
            sys.exit(str(error))
        else:
            conf.close()
            full_config[filename] = copy.copy(config_data)

    if not full_config:
        sys.exit('No data was found in configuraton, emmpty files?')

    return full_config


def configuration_check(config):
    """Perform a sanity check on configuration"""

    for filename in config:
        for option in OPTIONS_TYPE:
            if option not in config[filename]:
                sys.exit("{fh}: {option} isn't configured".format(
                    fh=filename,
                    option=option))
            if not isinstance(config[filename][option],
                              OPTIONS_TYPE[option]):
                sys.exit("{fh}: value({val}) for option '{option}' should be a"
                         " type of {otype}".format(
                             fh=filename, val=config[filename][option],
                             option=option,
                             otype=OPTIONS_TYPE[option].__name__))

        if (config[filename]['on_disabled'] != 'withdraw' and
                config[filename]['on_disabled'] != 'advertise'):
            sys.exit("{fh}: on_disable option has invalid value({val}), it "
                     "should be either 'withdraw' or 'advertise'".format(
                         fh=filename,
                         val=config[filename]['on_disabled']))

        # check if it is a valid IP
        if not valid_ip_prefix(config[filename]['ip_prefix']):
            sys.exit("{fh}: value({val}) for option 'ip_prefix' is invalid."
                     "It should be an IP PREFIX in form of <valid ip>/"
                     "<prefixlen>.".format(fh=filename,
                                           val=config[filename]['ip_prefix']))

        cmd = config[filename]['check_cmd'].split()
        try:
            proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
            proc.kill()
        except (OSError, subprocess.SubprocessError) as error:
            sys.exit("{fh}: failed to run {cmd} with {err}".format(
                fh=filename,
                cmd=config[filename]['check_cmd'],
                err=str(error)))


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
