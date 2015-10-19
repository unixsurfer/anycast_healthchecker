# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# pylint: disable=superfluous-parens
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals

import re
import os


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
    except (OSError, IOError) as error:
        print("Failed to touch file:{fh} error:{err}".format(fh=file_path,
                                                             err=error))
        return False
    else:
        fh.close()
        return True
