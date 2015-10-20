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


def configuration_check(cfg_dir):
    """Perform a sanity check on configuration"""
    files = []

    for name in glob.glob(os.path.join(cfg_dir, '*.json')):
        files.append(name)
    if not files:
        sys.exit("No configuration was found in {}".format(cfg_dir))

    for filename in files:
        try:
            with open(filename, 'r') as conf:
                config = json.load(conf)
        except ValueError as error:
            sys.exit("{fh}: isn't a valid JSON file: {err}".format(
                fh=filename,
                err=str(error)))
        except OSError as error:
            sys.exit("Failed to parse with error:{}".format(str(error)))

        for option in OPTIONS_TYPE:
            if option not in config:
                sys.exit("{fh}: {option} isn't configured".format(
                    fh=filename,
                    option=option))
            if not isinstance(config[option], OPTIONS_TYPE[option]):
                sys.exit("{fh}: value for option {option} should a type of "
                         "{otype}".format(fh=filename,
                                          option=option,
                                          otype=OPTIONS_TYPE[option].__name__))

        if (config['on_disabled'] != 'withdraw' and
                config['on_disabled'] != 'advertise'):
            sys.exit("{fh}: on_disable option has invalid value({val}), it "
                     "should be either 'withdraw' or 'advertise'".format(
                         fh=filename,
                         val=config['on_disabled']))

        # check if it is a valid IP
        if not valid_ip_prefix(config['ip_prefix']):
            sys.exit("{fh}: value({val}) for option 'ip_prefix' is invalid."
                     "It should be an IP PREFIX in form of <valid ip>/"
                     "<prefixlen>.".format(fh=filename,
                                           val=config['ip_prefix']))

        cmd = config['check_cmd'].split()
        try:
            proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
            proc.kill()
        except (OSError, subprocess.SubprocessError) as error:
            sys.exit("{fh}: failed to run {cmd} with {err}".format(
                fh=filename,
                cmd=config['check_cmd'],
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
