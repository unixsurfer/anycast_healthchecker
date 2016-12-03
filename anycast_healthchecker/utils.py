# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
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
import time
import datetime
import configparser
import glob
import copy
import shlex
import shutil
import ipaddress

from anycast_healthchecker import DEFAULT_OPTIONS

SERVICE_OPTIONS_TYPE = {
    'check_cmd': 'get',
    'check_interval': 'getint',
    'check_timeout': 'getint',
    'check_rise': 'getint',
    'check_fail': 'getint',
    'check_disabled': 'getboolean',
    'on_disabled': 'get',
    'ip_prefix': 'get',
    'interface': 'get',
    'ip_check_disabled': 'getboolean',
}
DAEMON_OPTIONS_TYPE = {
    'pidfile': 'get',
    'bird_conf': 'get',
    'bird6_conf': 'get',
    'bird_variable': 'get',
    'bird6_variable': 'get',
    'log_maxbytes': 'getint',
    'log_backups': 'getint',
    'log_file': 'get',
    'stderr_file': 'get',
    'stdout_file': 'get',
    'purge_ip_prefixes': 'getboolean',
    'bird_keep_changes': 'getboolean',
    'bird6_keep_changes': 'getboolean',
    'bird_changes_counter': 'getint',
    'bird6_changes_counter': 'getint',
    'bird_reconfigure_cmd': 'get',
    'bird6_reconfigure_cmd': 'get',
}


def valid_ip_prefix(ip_prefix):
    """Perform a sanity check on ip_prefix

    Arguments:
        ip_prefix (str): The IP-Prefix to validate

    Returns:
        True if ip_prefix is a valid IPv4 address with prefix length 32 or a
        valid IPv6 address with prefix length 128, otherwise False
    """
    try:
        ip_prefix = ipaddress.ip_network(ip_prefix)
    except ValueError:
        return False
    else:
        if ip_prefix.version == 4 and ip_prefix.max_prefixlen != 32:
            return False
        if ip_prefix.version == 6 and ip_prefix.max_prefixlen != 128:
            return False
        return True


def touch(file_path):
    """Touch a file in the same way as touch tool does.

    NOTE:
        If file_path doesn't exist it will be created.

    Arguments:
        file_path (str): The absolute file path
    """
    with open(file_path, 'a'):
        os.utime(file_path, None)


def get_ip_prefixes_from_config(config, services, ip_version):
    """Build a set of IP prefixes found in configuration files.

    Arguments:
        config (obg): A configparser object which holds our configuration.
        services (list): A list of section names which are the name of the
        service checks.
        ip_version (int): IP protocol version

    Returns:
        A set of IP prefixes.
    """

    ip_prefixes = set()

    for service in services:
        ip_prefix = ipaddress.ip_network(config.get(service, 'ip_prefix'))
        if ip_prefix.version == ip_version:
            ip_prefixes.add(config.get(service, 'ip_prefix'))

    return ip_prefixes


def service_configuration_check(config):
    """Perform a sanity check against options for each service check

    Arguments:
        config (obj): A configparser object which holds our configuration.

    Returns:
        None if all sanity checks are successfully passed otherwise raises a
        ValueError exception.
    """
    ipv4_enabled = config.getboolean('daemon', 'ipv4')
    ipv6_enabled = config.getboolean('daemon', 'ipv6')
    services = config.sections()
    services.remove('daemon')  # we don't need it during sanity check.

    for service in services:
        for option, getter in SERVICE_OPTIONS_TYPE.items():
            try:
                getattr(config, getter)(service, option)
            except configparser.Error as error:
                raise ValueError(error)
            except ValueError as exc:
                msg = ("invalid data for '{opt}' option in service check "
                       "{name}: {err}"
                       .format(opt=option, name=service, err=exc))
                raise ValueError(msg)

        if (config.get(service, 'on_disabled') != 'withdraw' and
                config.get(service, 'on_disabled') != 'advertise'):
            msg = ("'on_disable' option has invalid value ({val}) for "
                   "service check {name} should be either 'withdraw' or "
                   "'advertise'"
                   .format(name=service,
                           val=config.get(service, 'on_disabled')))
            raise ValueError(msg)

        if not valid_ip_prefix(config.get(service, 'ip_prefix')):
            msg = ("invalid value ({val}) for 'ip_prefix' option in service "
                   "check {name}. It should be an IP PREFIX in form of "
                   "ip/prefixlen."
                   .format(name=service, val=config.get(service, 'ip_prefix')))
            raise ValueError(msg)

        _ip_prefix = ipaddress.ip_network(config.get(service, 'ip_prefix'))
        if not ipv6_enabled and _ip_prefix.version == 6:
            raise ValueError("IPv6 support is disabled while there is an IPv6 "
                             "prefix configured for {name} service check"
                             .format(name=service))
        if not ipv4_enabled and _ip_prefix.version == 4:
            raise ValueError("IPv4 support is disabled while there is an IPv4 "
                             "prefix configured for {name} service check"
                             .format(name=service))

        cmd = shlex.split(config.get(service, 'check_cmd'))
        try:
            proc = subprocess.Popen(cmd)
            proc.kill()
        except (OSError, subprocess.SubprocessError) as exc:
            msg = ("failed to run check command '{cmd}' for service check "
                   "{name}: {err}"
                   .format(name=service,
                           cmd=config.get(service, 'check_cmd'),
                           err=exc))
            raise ValueError(msg)


def ip_prefixes_sanity_check(log, config, bird_configuration):
    """Sanity check on IP prefixes.

    - Exits main program if dummy_ip_prefix is invalid

    Arguments:
        log(logger obj): A logger object to use for emitting messages
        config (obg): A configparser object which holds our configuration.
        bird_configuration (dict): A dictionary, which holds Bird configuration
        per IP protocol version.
    """

    for ip_version in bird_configuration:
        modify_ip_prefixes(log,
                           config,
                           bird_configuration[ip_version]['config_file'],
                           bird_configuration[ip_version]['variable_name'],
                           bird_configuration[ip_version]['dummy_ip_prefix'],
                           bird_configuration[ip_version]['reconfigure_cmd'],
                           bird_configuration[ip_version]['keep_changes'],
                           bird_configuration[ip_version]['changes_counter'],
                           ip_version)


def modify_ip_prefixes(
        log,
        config,
        config_file,
        variable_name,
        dummy_ip_prefix,
        reconfigure_cmd,
        keep_changes,
        changes_counter,
        ip_version):
    """Modify IP prefixes in Bird configuration.

    - Depending on the configuration either remove or report IP prefixes found
    in Bird configuration for which we don't have a service check associated
    with them.
    - Add ``dummy_ip_prefix`` in Bird configuration if it is missing

    Arguments:
        log(logger obj): A logger object to use for emitting messages
        config (obg): A configparser object which holds our configuration.
        config_file (str): The file name of bird configuration
        variable_name (str): The name of the variable set in bird configuration
        dummy_ip_prefix (str): The dummy IP prefix, which must be always
        reconfigure_cmd (str): The command to run to trigger a reconfiguration
        on Bird daemon upon successful configuration update
        keep_changes (boolean): To enable keeping a history of changes applied
        to bird configuration
        changes_counter (int): The number of configuration changes to keep
        ip_version (int): IP protocol version of Bird configuration
    """
    services = config.sections()
    services.remove('daemon')  # not needed during sanity check for IP-Prefixes
    update_bird_conf = False

    try:
        ip_prefixes_in_bird = get_ip_prefixes_from_bird(config_file)
    except OSError as error:
        msg = ("failed to open Bird configuration {e}, this is a FATAL "
               "error, thus exiting main program"
               .format(e=error))
        log.error(msg, priority=80)
        sys.exit(1)

    if dummy_ip_prefix not in ip_prefixes_in_bird:
        log.warning("dummy IP prefix {ip} is missing from bird configuration "
                    "{fh}, adding it"
                    .format(ip=dummy_ip_prefix, fh=config_file))
        ip_prefixes_in_bird.insert(0, dummy_ip_prefix)
        update_bird_conf = True

    # Find IP prefixes in Bird configuration without a check.
    ip_prefixes_with_check = get_ip_prefixes_from_config(
        config,
        services,
        ip_version)
    # dummy_ip_prefix doesn't have a config by design
    ip_prefixes_with_check.add(dummy_ip_prefix)

    ip_prefixes_without_check = set(ip_prefixes_in_bird).difference(
        ip_prefixes_with_check)

    if ip_prefixes_without_check:
        if config.getboolean('daemon', 'purge_ip_prefixes'):
            log.warning("removing IP prefix(es) {i} from {fh} because they "
                        "don't have a service check configured"
                        .format(fh=config_file,
                                i=','.join(ip_prefixes_without_check)))
            ip_prefixes_in_bird[:] = (ip for ip in ip_prefixes_in_bird
                                      if ip not in ip_prefixes_without_check)
            update_bird_conf = True
        else:
            log.warning("found IP prefixes {i} in {fh} without a service "
                        "check configured"
                        .format(fh=config_file,
                                i=','.join(ip_prefixes_without_check)))

    # Either dummy IP-Prefix was added or unconfigured IP-Prefix(es) were
    # removed
    if update_bird_conf:
        if keep_changes:
            archive_bird_conf(log, config_file, changes_counter)
        tempname = write_temp_bird_conf(
            log,
            dummy_ip_prefix,
            config_file,
            variable_name,
            ip_prefixes_in_bird
        )
        try:
            os.rename(tempname, config_file)
        except OSError as error:
            msg = ("CRITICAL: failed to create Bird configuration {e}, "
                   "this is FATAL error, thus exiting main program"
                   .format(e=error))
            sys.exit("{m}".format(m=msg))
        else:
            log.info("Bird configuration for IPv{v} is updated"
                     .format(v=ip_version))
            reconfigure_bird(log, reconfigure_cmd)


def load_configuration(config_file, config_dir, service_file):
    """Build configuration objects.

    If all sanity checks against daemon and service check settings are passed
    then it builds a ConfigParser object which holds all our configuration
    and a dictionary data structure which holds Bird configuration per IP
    protocol version.

    Arguments:
        config_file (str): The file name which holds daemon settings
        config_dir (str): The directory name which has configuration files
        for each service check
        service_file (str): A file which contains configuration for a single
        service check

    Returns:
        A tuple with 1st element a ConfigParser object and 2nd element
        a dictionary.
    """
    config_files = [config_file]
    defaults = copy.copy(DEFAULT_OPTIONS['DEFAULT'])
    daemon_defaults = {
        'daemon': copy.copy(DEFAULT_OPTIONS['daemon'])
    }
    config = configparser.ConfigParser(defaults=defaults)
    config.read_dict(daemon_defaults)
    if service_file is not None:
        if not os.path.isfile(service_file):
            print("{f} configuration file for a service check doesn't exist"
                  .format(f=service_file))
        else:
            config_files.append(service_file)
    elif config_dir is not None:
        if not os.path.isdir(config_dir):
            print("{d} directory with configuratin files for service checks "
                  "doesn't exist".format(d=config_dir))
        else:
            config_files.extend(glob.glob(os.path.join(config_dir, '*.conf')))

    try:
        config.read(config_files)
    except configparser.Error as exc:
        raise ValueError(exc)

    configuration_check(config)

    bird_configuration = {}
    if config.getboolean('daemon', 'ipv4'):
        bird_configuration[4] = {
            'config_file': config.get('daemon', 'bird_conf'),
            'variable_name': config.get('daemon', 'bird_variable'),
            'dummy_ip_prefix': config.get('daemon', 'dummy_ip_prefix'),
            'reconfigure_cmd': config.get('daemon', 'bird_reconfigure_cmd'),
            'keep_changes': config.get('daemon', 'bird_keep_changes'),
            'changes_counter': config.getint('daemon', 'bird_changes_counter')
        }
    if config.getboolean('daemon', 'ipv6'):
        bird_configuration[6] = {
            'config_file': config.get('daemon', 'bird6_conf'),
            'variable_name': config.get('daemon', 'bird6_variable'),
            'dummy_ip_prefix': config.get('daemon', 'dummy_ip6_prefix'),
            'reconfigure_cmd': config.get('daemon', 'bird6_reconfigure_cmd'),
            'keep_changes': config.get('daemon', 'bird6_keep_changes'),
            'changes_counter': config.getint('daemon', 'bird6_changes_counter')
        }

    return config, bird_configuration


def configuration_check(config):
    """Perform a sanity check on configuration

    First it performs a sanity check against settings for daemon
    and then agaist settings for each service check.

    Arguments:
        config (obj): A configparser object which holds our configuration.

    Returns:
        None if all checks are successfully passed otherwise raises a
        ValueError exception.
    """
    log_level = config.get('daemon', 'loglevel')
    num_level = getattr(logging, log_level.upper(), None)
    if not isinstance(num_level, int):
        raise ValueError('Invalid log level: {}'.format(log_level))

    for _file in 'log_file', 'stdout_file', 'stderr_file':
        try:
            touch(config.get('daemon', _file))
        except OSError as exc:
            raise ValueError(exc)

    for option, getter in DAEMON_OPTIONS_TYPE.items():
        try:
            getattr(config, getter)('daemon', option)
        except configparser.Error as error:
            raise ValueError(error)
        except ValueError as exc:
            msg = ("invalid data for '{opt}' option in daemon section: {err}"
                   .format(opt=option, err=exc))
            raise ValueError(msg)

    if config.getboolean('daemon', 'ipv4'):
        try:
            touch(config.get('daemon', 'bird_conf'))
        except OSError as exc:
            raise ValueError(exc)

        _dummy_ip_prefix = config.get('daemon', 'dummy_ip_prefix')
        if not valid_ip_prefix(_dummy_ip_prefix):
            raise ValueError("invalid dummy IPv4 prefix: {i}"
                             .format(i=_dummy_ip_prefix))

    if config.getboolean('daemon', 'ipv6'):
        try:
            touch(config.get('daemon', 'bird_conf'))
        except OSError as exc:
            raise ValueError(exc)

        _dummy_ip_prefix = config.get('daemon', 'dummy_ip6_prefix')
        if not valid_ip_prefix(_dummy_ip_prefix):
            raise ValueError("invalid dummy IPv6 prefix: {i}"
                             .format(i=_dummy_ip_prefix))

    service_configuration_check(config)


def running(processid):
    """Check the validity of a process ID.

    Arguments:
        processid (int): Process ID number.

    Returns:
        True if process ID is found otherwise False.
    """
    try:
        # From kill(2)
        #   If sig is 0 (the null signal), error checking is performed but no
        #   signal is actually sent. The null signal can be used to check the
        #   validity of pid
        os.kill(processid, 0)
    except OSError:
        return False
    else:
        return True


def get_ip_prefixes_from_bird(filename):
    """Build a list of IP prefixes found in Bird configuration

    Arguments:
        filename (str): The absolute path of the Bird configuration file.

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
    with open(filename, 'r') as bird_conf:
        lines = bird_conf.read()

    for line in lines.splitlines():
        line = line.strip(', ')
        if valid_ip_prefix(line):
            prefixes.append(line)

    return prefixes


class BaseOperation(object):
    """Run operation on a list


    Arguments:
        name (string): The name of the service for the given ip_prefix
        ip_prefix (string): The value to run the operation
        log (logger obj): A logger object to use for emitting messages
        extra (dictionary): A possible dictionary structure to pass further
    """
    def __init__(self, name, ip_prefix, log, ip_version, **extra):
        self.name = name
        self.ip_prefix = ip_prefix
        self.log = log
        self.ip_version = ip_version
        self.extra = extra


class AddOperation(BaseOperation):
    """Add a value to a list"""
    def __str__(self):
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
    """Remove a value from a list"""
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


def reconfigure_bird(log, cmd):
    """Reload BIRD daemon.

    Arguments:
        log (logger obj): A logger object to use for emitting messages
        cmd (string): A command to trigger a reconfiguration of Bird daemon

    Notes:
        Runs 'birdc configure' to reload BIRD. Some useful information on how
        birdc tool works:
            -- Returns a non-zero exit code only when it can't access BIRD
               daemon via the control socket (/var/run/bird.ctl). This happens
               when BIRD daemon is either down or when the caller of birdc
               doesn't have access to the control socket.
            -- Returns zero exit code when reload fails due to invalid
               configuration. Thus, we catch this case by looking at the output
               and not at the exit code.
            -- Returns zero exit code when reload was successful.
            -- Should never timeout, if it does then it is a bug.
    """
    cmd = shlex.split(cmd)
    log.info("reloading BIRD by running {c}".format(c=' '.join(cmd)))
    try:
        output = subprocess.check_output(
            cmd,
            timeout=2,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            )
    except subprocess.TimeoutExpired:
        log.error("reloading bird timed out", priority=80)
        return
    except subprocess.CalledProcessError as error:
        # birdc returns 0 even when it fails due to invalid config,
        # but it returns 1 when BIRD is down.
        msg = ("reloading BIRD failed, either BIRD daemon is down or we don't "
               "have privileges to reconfigure it (sudo problems?):{e}"
               .format(e=error.output.strip()))
        log.error(msg, priority=80)
        return
    except FileNotFoundError as error:
        msg = "reloading BIRD failed with: {e}".format(e=error)
        log.error(msg, priority=80)
        return

    # 'Reconfigured' string will be in the output if and only if conf is valid.
    pattern = re.compile('^Reconfigured$', re.MULTILINE)
    if pattern.search(str(output)):
        log.info('reloaded BIRD daemon')
    else:
        # We will end up here only if we generated an invalid conf
        # or someone broke bird.conf.
        msg = ("reloading BIRD returned error, most likely we generated "
               "an invalid configuration file or Bird configuration in "
               "general is broken:{e}".format(e=output))
        log.error(msg, priority=80)


def write_temp_bird_conf(log,
                         dummy_ip_prefix,
                         config_file,
                         variable_name,
                         prefixes):
    """Write in a temporary file the list of IP-Prefixes

    A failure to create and write the temporary file will exit main program.

    Arguments:
        log(logger obj): A logger object to use for emitting messages
        dummy_ip_prefix (str): The dummy IP prefix, which must be always
        config_file (str): The file name of bird configuration
        variable_name (str): The name of the variable set in bird configuration
        prefixes (list): The list of IP-Prefixes to write

    Returns:
        The filename of the temporary file
    """
    comment = ("# {i} is a dummy IP Prefix. It should NOT be used and "
               "REMOVED from the constant.".format(i=dummy_ip_prefix))

    # the temporary file must be on the same filesystem as the bird config
    # as we use os.rename to perform an atomic update on the bird config.
    # Thus, we create it in the same directory that bird config is stored.
    tm_file = os.path.dirname(config_file) + '/' + str(time.time())
    log.debug("going to write to {f}".format(f=tm_file), json_blob=False)

    try:
        with open(tm_file, 'w') as tmpf:
            tmpf.write("# Generated {t} by anycast-healthchecker (pid={p})\n"
                       .format(t=datetime.datetime.now(), p=os.getpid()))
            tmpf.write("{c}\n".format(c=comment))
            tmpf.write("define {n} =\n".format(n=variable_name))
            tmpf.write("{s}[\n".format(s=4 * ' '))
            # all entries of the array need a trailing comma except the last
            # one. A single element array doesn't need a trailing comma.
            tmpf.write(',\n'.join([' '*8 + n for n in prefixes]))
            tmpf.write("\n{s}];\n".format(s=4 * ' '))
    except OSError as error:
        msg = ("failed to write temporary file {f}: {e}. This is a FATAL "
               "error, this exiting main program"
               .format(f=tm_file, e=error))
        log.critical(msg, priority=80)
        sys.exit(1)
    else:
        return tm_file


def archive_bird_conf(log,
                      config_file,
                      changes_counter):
    """Keep a history of Bird configuration files

    Arguments:
        log (logger obj): A logger object to use for emitting messages
        config_file (str): The file name of bird configuration
        changes_counter (int): How many configuration files to keep in the
        history
    """
    history_dir = os.path.join(
        os.path.dirname(os.path.realpath(config_file)),
        'history'
    )
    dst = os.path.join(history_dir, str(time.time()))
    log.debug("coping {s} to {d}"
              .format(s=config_file, d=dst), json_blob=False)
    history = [x for x in os.listdir(history_dir)
               if os.path.isfile(os.path.join(history_dir, x))]

    if len(history) > changes_counter:
        log.info("threshold ({n}) is reached, removing old files"
                 .format(n=changes_counter))
        for _file in sorted(history, reverse=True)[changes_counter - 1:]:
            _path = os.path.join(history_dir, _file)
            try:
                os.remove(_path)
            except OSError as exc:
                log.warning("failed to remove {f}: {e}".format(f=_file, e=exc))
            else:
                log.info("removed {f}".format(f=_path))

    try:
        shutil.copy2(config_file, dst)
    except OSError as exc:
        log.warning("failed to copy {s} to {d}: {e}"
                    .format(s=config_file, d=dst, e=exc))
