# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-lines
"""Provide functions and classes that are used within anycast_healthchecker."""
from collections import Counter
import re
import os
import sys
import subprocess
import logging
import logging.handlers
import time
import datetime
import configparser
import glob
import copy
import shlex
import shutil
import ipaddress

from pythonjsonlogger import jsonlogger

from anycast_healthchecker import DEFAULT_OPTIONS, PROGRAM_NAME, __version__

SERVICE_OPTIONS_TYPE = {
    'check_cmd': 'get',
    'check_interval': 'getfloat',
    'check_timeout': 'getfloat',
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
    'stderr_log_server': 'getboolean',
    'log_server': 'get',
    'log_server_port': 'getint',
    'json_stdout': 'getboolean',
    'json_log_server': 'getboolean',
    'json_log_file': 'getboolean',
    'purge_ip_prefixes': 'getboolean',
    'bird_keep_changes': 'getboolean',
    'bird6_keep_changes': 'getboolean',
    'bird_changes_counter': 'getint',
    'bird6_changes_counter': 'getint',
    'bird_reconfigure_cmd': 'get',
    'bird6_reconfigure_cmd': 'get',
}
DAEMON_OPTIONAL_OPTIONS = [
    'stderr_log_server',
    'stderr_file',
    'log_server',
    'log_file',
]


def valid_ip_prefix(ip_prefix):
    """Perform a sanity check on ip_prefix.

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

    Returns:
        None

    Raises:
        OSError exception

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
            ip_prefixes.add(ip_prefix.with_prefixlen)

    return ip_prefixes


def ip_prefixes_sanity_check(config, bird_configuration):
    """Sanity check on IP prefixes.

    Arguments:
        config (obg): A configparser object which holds our configuration.
        bird_configuration (dict): A dictionary, which holds Bird configuration
        per IP protocol version.

    """
    for ip_version in bird_configuration:
        modify_ip_prefixes(config,
                           bird_configuration[ip_version]['config_file'],
                           bird_configuration[ip_version]['variable_name'],
                           bird_configuration[ip_version]['dummy_ip_prefix'],
                           bird_configuration[ip_version]['reconfigure_cmd'],
                           bird_configuration[ip_version]['keep_changes'],
                           bird_configuration[ip_version]['changes_counter'],
                           ip_version)


def modify_ip_prefixes(
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
    log = logging.getLogger(PROGRAM_NAME)
    services = config.sections()
    services.remove('daemon')  # not needed during sanity check for IP-Prefixes
    update_bird_conf = False
    try:
        ip_prefixes_in_bird = get_ip_prefixes_from_bird(config_file)
    except OSError as error:
        log.error("failed to open Bird configuration %s, this is a FATAL "
                  "error, thus exiting main program", error)
        sys.exit(1)

    if dummy_ip_prefix not in ip_prefixes_in_bird:
        log.warning("dummy IP prefix %s is missing from bird configuration "
                    "%s, adding it", dummy_ip_prefix, config_file)
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
            log.warning("removing IP prefix(es) %s from %s because they don't "
                        "have a service check configured",
                        ','.join(ip_prefixes_without_check),
                        config_file)
            ip_prefixes_in_bird[:] = (ip for ip in ip_prefixes_in_bird
                                      if ip not in ip_prefixes_without_check)
            update_bird_conf = True
        else:
            log.warning("found IP prefixes %s in %s without a service "
                        "check configured",
                        ','.join(ip_prefixes_without_check),
                        config_file)

    # Either dummy IP-Prefix was added or an IP-Prefix(es) without a service
    # check was removed.
    if update_bird_conf:
        if keep_changes:
            archive_bird_conf(config_file, changes_counter)
        tempname = write_temp_bird_conf(
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
            log.info("Bird configuration for IPv%s is updated", ip_version)
            reconfigure_bird(reconfigure_cmd)


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
            raise ValueError("{f} configuration file for a service check "
                             "doesn't exist".format(f=service_file))
        else:
            config_files.append(service_file)
    elif config_dir is not None:
        if not os.path.isdir(config_dir):
            raise ValueError("{d} directory with configuration files for "
                             "service checks doesn't exist"
                             .format(d=config_dir))
        else:
            config_files.extend(glob.glob(os.path.join(config_dir, '*.conf')))

    try:
        config.read(config_files)
    except configparser.Error as exc:
        raise ValueError(exc)

    configuration_check(config)
    bird_configuration = build_bird_configuration(config)
    create_bird_config_files(bird_configuration)

    return config, bird_configuration


def configuration_check(config):
    """Perform a sanity check on configuration.

    First it performs a sanity check against settings for daemon
    and then against settings for each service check.

    Arguments:
        config (obj): A configparser object which holds our configuration.

    Returns:
        None if all checks are successfully passed otherwise raises a
        ValueError exception.

    """
    log_level = config.get('daemon', 'loglevel')
    num_level = getattr(logging, log_level.upper(), None)
    pidfile = config.get('daemon', 'pidfile')

    # Catch the case where the directory, under which we store the pid file, is
    # missing.
    if not os.path.isdir(os.path.dirname(pidfile)):
        raise ValueError("{d} doesn't exit".format(d=os.path.dirname(pidfile)))

    if not isinstance(num_level, int):
        raise ValueError('Invalid log level: {}'.format(log_level))

    for _file in 'log_file', 'stderr_file':
        if config.has_option('daemon', _file):
            try:
                touch(config.get('daemon', _file))
            except OSError as exc:
                raise ValueError(exc)

    for option, getter in DAEMON_OPTIONS_TYPE.items():
        try:
            getattr(config, getter)('daemon', option)
        except configparser.NoOptionError as error:
            if option not in DAEMON_OPTIONAL_OPTIONS:
                raise ValueError(error)
        except configparser.Error as error:
            raise ValueError(error)
        except ValueError as exc:
            msg = ("invalid data for '{opt}' option in daemon section: {err}"
                   .format(opt=option, err=exc))
            raise ValueError(msg)

    service_configuration_check(config)


def service_configuration_check(config):
    """Perform a sanity check against options for each service check.

    Arguments:
        config (obj): A configparser object which holds our configuration.

    Returns:
        None if all sanity checks are successfully passed otherwise raises a
        ValueError exception.

    """
    ipv4_enabled = config.getboolean('daemon', 'ipv4')
    ipv6_enabled = config.getboolean('daemon', 'ipv6')
    services = config.sections()
    # we don't need it during sanity check for services check
    services.remove('daemon')
    ip_prefixes = []

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
            msg = ("'on_disabled' option has invalid value ({val}) for "
                   "service check {name}, 'on_disabled option should be set "
                   "either to 'withdraw' or to 'advertise'"
                   .format(name=service,
                           val=config.get(service, 'on_disabled')))
            raise ValueError(msg)

        ip_prefixes.append(config.get(service, 'ip_prefix'))

        if not valid_ip_prefix(config.get(service, 'ip_prefix')):
            msg = ("invalid value ({val}) for 'ip_prefix' option in service "
                   "check {name}. It should be an IP PREFIX in form of "
                   "ip/prefixlen."
                   .format(name=service, val=config.get(service, 'ip_prefix')))
            raise ValueError(msg)

        _ip_prefix = ipaddress.ip_network(config.get(service, 'ip_prefix'))
        if not ipv6_enabled and _ip_prefix.version == 6:
            raise ValueError("IPv6 support is disabled in "
                             "anycast-healthchecker while there is an IPv6 "
                             "prefix configured for {name} service check"
                             .format(name=service))
        if not ipv4_enabled and _ip_prefix.version == 4:
            raise ValueError("IPv4 support is disabled in "
                             "anycast-healthchecker while there is an IPv4 "
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

    occurrences_of_ip_prefixes = Counter(ip_prefixes)
    for ip_prefix, counter in occurrences_of_ip_prefixes.items():
        if counter > 1:
            raise ValueError("{ip} is used by {c} service checks"
                             .format(ip=ip_prefix, c=counter))


def build_bird_configuration(config):
    """Build bird configuration structure.

    First it performs a sanity check against bird settings and then builds a
    dictionary structure with bird configuration per IP version.

    Arguments:
        config (obj): A configparser object which holds our configuration.

    Returns:
        A dictionary

    Raises:
        ValueError if sanity check fails.

    """
    bird_configuration = {}

    if config.getboolean('daemon', 'ipv4'):
        if os.path.islink(config.get('daemon', 'bird_conf')):
            config_file = os.path.realpath(config.get('daemon', 'bird_conf'))
            print("'bird_conf' is set to a symbolic link ({s} -> {d}, but we "
                  "will use the canonical path of that link"
                  .format(s=config.get('daemon', 'bird_conf'), d=config_file))
        else:
            config_file = config.get('daemon', 'bird_conf')

        dummy_ip_prefix = config.get('daemon', 'dummy_ip_prefix')
        if not valid_ip_prefix(dummy_ip_prefix):
            raise ValueError("invalid dummy IPv4 prefix: {i}"
                             .format(i=dummy_ip_prefix))

        bird_configuration[4] = {
            'config_file': config_file,
            'variable_name': config.get('daemon', 'bird_variable'),
            'dummy_ip_prefix': dummy_ip_prefix,
            'reconfigure_cmd': config.get('daemon', 'bird_reconfigure_cmd'),
            'keep_changes': config.getboolean('daemon', 'bird_keep_changes'),
            'changes_counter': config.getint('daemon', 'bird_changes_counter')
        }
    if config.getboolean('daemon', 'ipv6'):
        if os.path.islink(config.get('daemon', 'bird6_conf')):
            config_file = os.path.realpath(config.get('daemon', 'bird6_conf'))
            print("'bird6_conf' is set to a symbolic link ({s} -> {d}, but we "
                  "will use the canonical path of that link"
                  .format(s=config.get('daemon', 'bird6_conf'), d=config_file))
        else:
            config_file = config.get('daemon', 'bird6_conf')

        dummy_ip_prefix = config.get('daemon', 'dummy_ip6_prefix')
        if not valid_ip_prefix(dummy_ip_prefix):
            raise ValueError("invalid dummy IPv6 prefix: {i}"
                             .format(i=dummy_ip_prefix))
        bird_configuration[6] = {
            'config_file': config_file,
            'variable_name': config.get('daemon', 'bird6_variable'),
            'dummy_ip_prefix': dummy_ip_prefix,
            'reconfigure_cmd': config.get('daemon', 'bird6_reconfigure_cmd'),
            'keep_changes': config.getboolean('daemon', 'bird6_keep_changes'),
            'changes_counter': config.getint('daemon', 'bird6_changes_counter')
        }

    return bird_configuration


def create_bird_config_files(bird_configuration):
    """Create bird configuration files per IP version.

    Creates bird configuration files if they don't exist. It also creates the
    directories where we store the history of changes, if this functionality is
    enabled.

    Arguments:
        bird_configuration (dict): A dictionary with settings for bird.

    Returns:
       None

    Raises:
        ValueError if we can't create bird configuration files and the
        directory to store the history of changes in bird configuration file.

    """
    for ip_version in bird_configuration:
        # This creates the file if it doesn't exist.
        config_file = bird_configuration[ip_version]['config_file']
        try:
            touch(config_file)
        except OSError as exc:
            raise ValueError("failed to create {f}:{e}"
                             .format(f=config_file, e=exc))
        if bird_configuration[ip_version]['keep_changes']:
            history_dir = os.path.join(os.path.dirname(config_file), 'history')
            try:
                os.mkdir(history_dir)
            except FileExistsError:
                pass
            except OSError as exc:
                raise ValueError("failed to make directory {d} for keeping a "
                                 "history of changes for {b}:{e}"
                                 .format(d=history_dir, b=config_file, e=exc))
            else:
                print("{d} is created".format(d=history_dir))


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
    except OverflowError as exc:
        print("checking validity of pid ({p}) failed with: {e}"
              .format(p=processid, e=exc))
        sys.exit(1)
    except OSError:
        return False
    else:
        return True


def get_ip_prefixes_from_bird(filename):
    """Build a list of IP prefixes found in Bird configuration.

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
    """Run operation on a list.

    Arguments:
        name (string): The name of the service for the given ip_prefix
        ip_prefix (string): The value to run the operation
    """

    def __init__(self, name, ip_prefix, ip_version):  # noqa:D102
        self.name = name
        self.ip_prefix = ip_prefix
        self.log = logging.getLogger(PROGRAM_NAME)
        self.ip_version = ip_version


class AddOperation(BaseOperation):
    """Add a value to a list."""

    def __str__(self):
        """Handy string representation."""
        return 'add to'

    def update(self, prefixes):
        """Add a value to the list.

        Arguments:
            prefixes(list): A list to add the value
        """
        if self.ip_prefix not in prefixes:
            prefixes.append(self.ip_prefix)
            self.log.info("announcing %s for %s", self.ip_prefix, self.name)
            return True

        return False


class DeleteOperation(BaseOperation):
    """Remove a value from a list."""

    def __str__(self):
        """Handy string representation."""
        return 'delete from'

    def update(self, prefixes):
        """Remove a value to the list.

        Arguments:
            prefixes(list): A list to remove the value
        """
        if self.ip_prefix in prefixes:
            prefixes.remove(self.ip_prefix)
            self.log.info("withdrawing %s for %s", self.ip_prefix, self.name)
            return True

        return False


def reconfigure_bird(cmd):
    """Reconfigure BIRD daemon.

    Arguments:
        cmd (string): A command to trigger a reconfiguration of Bird daemon

    Notes:
        Runs 'birdc configure' to reconfigure BIRD. Some useful information on
        how birdc tool works:
            -- Returns a non-zero exit code only when it can't access BIRD
               daemon via the control socket (/var/run/bird.ctl). This happens
               when BIRD daemon is either down or when the caller of birdc
               doesn't have access to the control socket.
            -- Returns zero exit code when reconfigure fails due to invalid
               configuration. Thus, we catch this case by looking at the output
               and not at the exit code.
            -- Returns zero exit code when reconfigure was successful.
            -- Should never timeout, if it does then it is a bug.

    """
    log = logging.getLogger(PROGRAM_NAME)
    cmd = shlex.split(cmd)
    log.info("reconfiguring BIRD by running %s", ' '.join(cmd))
    try:
        output = subprocess.check_output(
            cmd,
            timeout=2,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            )
    except subprocess.TimeoutExpired:
        log.error("reconfiguring bird timed out")
        return
    except subprocess.CalledProcessError as error:
        # birdc returns 0 even when it fails due to invalid config,
        # but it returns 1 when BIRD is down.
        log.error("reconfiguring BIRD failed, either BIRD daemon is down or "
                  "we don't have privileges to reconfigure it (sudo problems?)"
                  ":%s", error.output.strip())
        return
    except FileNotFoundError as error:
        log.error("reconfiguring BIRD failed with: %s", error)
        return

    # 'Reconfigured' string will be in the output if and only if conf is valid.
    pattern = re.compile('^Reconfigured$', re.MULTILINE)
    if pattern.search(str(output)):
        log.info('reconfigured BIRD daemon')
    else:
        # We will end up here only if we generated an invalid conf
        # or someone broke bird.conf.
        log.error("reconfiguring BIRD returned error, most likely we generated"
                  " an invalid configuration file or Bird configuration in is "
                  "broken:%s", output)


def write_temp_bird_conf(dummy_ip_prefix,
                         config_file,
                         variable_name,
                         prefixes):
    """Write in a temporary file the list of IP-Prefixes.

    A failure to create and write the temporary file will exit main program.

    Arguments:
        dummy_ip_prefix (str): The dummy IP prefix, which must be always
        config_file (str): The file name of bird configuration
        variable_name (str): The name of the variable set in bird configuration
        prefixes (list): The list of IP-Prefixes to write

    Returns:
        The filename of the temporary file

    """
    log = logging.getLogger(PROGRAM_NAME)
    comment = ("# {i} is a dummy IP Prefix. It should NOT be used and "
               "REMOVED from the constant.".format(i=dummy_ip_prefix))

    # the temporary file must be on the same filesystem as the bird config
    # as we use os.rename to perform an atomic update on the bird config.
    # Thus, we create it in the same directory that bird config is stored.
    tm_file = os.path.join(os.path.dirname(config_file), str(time.time()))
    log.debug("going to write to %s", tm_file)

    try:
        with open(tm_file, 'w') as tmpf:
            tmpf.write("# Generated {t} by {n} (pid={p})\n"
                       .format(t=datetime.datetime.now(),
                               n=PROGRAM_NAME,
                               p=os.getpid()))
            tmpf.write("{c}\n".format(c=comment))
            tmpf.write("define {n} =\n".format(n=variable_name))
            tmpf.write("{s}[\n".format(s=4 * ' '))
            # all entries of the array need a trailing comma except the last
            # one. A single element array doesn't need a trailing comma.
            tmpf.write(',\n'.join([' '*8 + n for n in prefixes]))
            tmpf.write("\n{s}];\n".format(s=4 * ' '))
    except OSError as error:
        log.critical("failed to write temporary file %s: %s. This is a FATAL "
                     "error, this exiting main program", tm_file, error)
        sys.exit(1)
    else:
        return tm_file


def archive_bird_conf(config_file, changes_counter):
    """Keep a history of Bird configuration files.

    Arguments:
        config_file (str): file name of bird configuration
        changes_counter (int): number of configuration files to keep in the
        history
    """
    log = logging.getLogger(PROGRAM_NAME)
    history_dir = os.path.join(os.path.dirname(config_file), 'history')
    dst = os.path.join(history_dir, str(time.time()))
    log.debug("coping %s to %s", config_file, dst)

    history = [x for x in os.listdir(history_dir)
               if os.path.isfile(os.path.join(history_dir, x))]

    if len(history) > changes_counter:
        log.info("threshold of %s is reached, removing old files",
                 changes_counter)
        for _file in sorted(history, reverse=True)[changes_counter - 1:]:
            _path = os.path.join(history_dir, _file)
            try:
                os.remove(_path)
            except OSError as exc:
                log.warning("failed to remove %s: %s", _file, exc)
            else:
                log.info("removed %s", _path)

    try:
        shutil.copy2(config_file, dst)
    except OSError as exc:
        log.warning("failed to copy %s to %s: %s", config_file, dst, exc)


def update_pidfile(pidfile):
    """Update pidfile.

    Notice:
        We should call this function only after we have successfully acquired
        a lock and never before. It exits main program if it fails to parse
        and/or write pidfile.

    Arguments:
        pidfile (str): pidfile to update

    """
    try:
        with open(pidfile, mode='r') as _file:
            pid = _file.read(1024).rstrip()

        try:
            pid = int(pid)
        except ValueError:
            print("cleaning stale pidfile with invalid data:'{}'".format(pid))
            write_pid(pidfile)
        else:
            if running(pid):
                # This is to catch migration issues from 0.7.x to 0.8.x
                # version, where old process is still around as it failed to
                # be stopped. Since newer version has a different locking
                # mechanism, we can end up with both versions running.
                # In order to avoid this situation we refuse to startup.
                sys.exit("process {} is already running".format(pid))
            else:
                # pidfile exists with a PID for a process that is not running.
                # Let's update PID.
                print("updating stale processID({}) in pidfile".format(pid))
                write_pid(pidfile)
    except FileNotFoundError:
        # Either it's 1st time we run or previous run was terminated
        # successfully.
        print("creating pidfile {f}".format(f=pidfile))
        write_pid(pidfile)
    except OSError as exc:
        sys.exit("failed to update pidfile:{e}".format(e=exc))


def write_pid(pidfile):
    """Write processID to the pidfile.

    Notice:
        It exits main program if it fails to write pidfile.

    Arguments:
        pidfile (str): pidfile to update

    """
    pid = str(os.getpid())
    try:
        with open(pidfile, mode='w') as _file:
            print("writing processID {p} to pidfile".format(p=pid))
            _file.write(pid)
    except OSError as exc:
        sys.exit("failed to write pidfile:{e}".format(e=exc))


def shutdown(pidfile, signalnb=None, frame=None):
    """Clean up pidfile upon shutdown.

    Notice:
        We should register this function as signal handler for the following
        termination signals:
            SIGHUP
            SIGTERM
            SIGABRT
            SIGINT

    Arguments:
        pidfile (str): pidfile to remove
        signalnb (int): The ID of signal
        frame (obj): Frame object at the time of receiving the signal

    """
    log = logging.getLogger(PROGRAM_NAME)
    log.info("received %s at %s", signalnb, frame)
    log.info("going to remove pidfile %s", pidfile)
    # no point to catch possible errors when we delete the pid file
    os.unlink(pidfile)
    log.info('shutdown is complete')
    sys.exit(0)


def setup_logger(config):
    """Configure the logging environment.

    Notice:
        By default logging will go to STDOUT and messages for unhandled
        exceptions or crashes will go to STDERR. If log_file and/or log_server
        is set then we don't log to STDOUT. Messages for unhandled exceptions
        or crashes can only go to either STDERR or to stderr_file or to
        stderr_log_server.

    Arguments:
        config (obj): A configparser object which holds our configuration.

    Returns:
        A logger with all possible handlers configured.

    """
    logger = logging.getLogger(PROGRAM_NAME)
    num_level = getattr(
        logging,
        config.get('daemon', 'loglevel').upper(),  # pylint: disable=no-member
        None
    )
    logger.setLevel(num_level)
    lengths = []
    for section in config:
        lengths.append(len(section))

    width = sorted(lengths)[-1] + 1

    def log_format():
        """Produce a log format line."""
        supported_keys = [
            'asctime',
            'levelname',
            'process',
            # 'funcName',
            # 'lineno',
            'threadName',
            'message',
        ]

        return ' '.join(['%({0:s})'.format(i) for i in supported_keys])

    custom_format = log_format()
    json_formatter = CustomJsonFormatter(custom_format,
                                         prefix=PROGRAM_NAME)
    formatter = logging.Formatter(
        '%(asctime)s {program}[%(process)d] %(levelname)-8s '
        '%(threadName)-{width}s %(message)s'
        .format(program=PROGRAM_NAME, width=width)
    )

    # Register logging handlers based on configuration.
    if config.has_option('daemon', 'log_file'):
        file_handler = logging.handlers.RotatingFileHandler(
            config.get('daemon', 'log_file'),
            maxBytes=config.getint('daemon', 'log_maxbytes'),
            backupCount=config.getint('daemon', 'log_backups')
        )

        if config.getboolean('daemon', 'json_log_file'):
            file_handler.setFormatter(json_formatter)
        else:
            file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if config.has_option('daemon', 'log_server'):
        udp_handler = logging.handlers.SysLogHandler(
            (
                config.get('daemon', 'log_server'),
                config.getint('daemon', 'log_server_port')
            )
        )

        if config.getboolean('daemon', 'json_log_server'):
            udp_handler.setFormatter(json_formatter)
        else:
            udp_handler.setFormatter(formatter)
        logger.addHandler(udp_handler)

    # Log to STDOUT if and only if log_file and log_server aren't enabled
    if (not config.has_option('daemon', 'log_file')
            and not config.has_option('daemon', 'log_server')):
        stream_handler = logging.StreamHandler()
        if config.getboolean('daemon', 'json_stdout'):
            stream_handler.setFormatter(json_formatter)
        else:
            stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    # We can redirect STDERR only to one destination.
    if config.has_option('daemon', 'stderr_file'):
        sys.stderr = CustomRotatingFileLogger(
            filepath=config.get('daemon', 'stderr_file'),
            maxbytes=config.getint('daemon', 'log_maxbytes'),
            backupcount=config.getint('daemon', 'log_backups')
        )
    elif (config.has_option('daemon', 'stderr_log_server')
          and not config.has_option('daemon', 'stderr_file')):
        sys.stderr = CustomUdpLogger(
            server=config.get('daemon', 'log_server'),
            port=config.getint('daemon', 'log_server_port')
        )
    else:
        print('messages for unhandled exceptions will go to STDERR')

    return logger


class CustomLogger(object):
    """Helper Logger to redirect STDOUT or STDERR to a logging hander.

    It wraps a Logger class into a file like object, which provides a handy
    way to redirect STDOUT or STDERR to a logger. This class provides the
    necessary methods (write, flush and close) to build a file-like object
    and it can not be used directly as it does not provide a logging handler.
    Instead, you must instantiate one of subclass (CustomRotatingFileLogger and
    CustomUdpLogger).

    Arguments
        handler (int): A logging handler to use.

    Methods:
        write(string): Write string to logger with newlines removed.
        flush(): Flushe logger messages.
        close(): Close logger.

    Returns:
        A logger object.

    """

    def __init__(self, handler):
        """Create a logging.Logger class with extended functionality."""
        log_format = ('%(asctime)s {program}[%(process)d] '
                      '%(threadName)s %(message)s'
                      .format(program=PROGRAM_NAME))
        self.logger = logging.getLogger('stderr')
        self.logger.setLevel(logging.DEBUG)
        self.handler = handler
        formatter = logging.Formatter(log_format)
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)

    def write(self, string):
        """Erase newline from a string and write to the logger."""
        string = string.rstrip()
        if string:  # Don't log empty lines
            self.logger.critical(string)

    def flush(self):
        """Flush logger's data."""
        # In case multiple handlers are attached to the logger make sure they
        # are flushed.
        for handler in self.logger.handlers:
            handler.flush()

    def close(self):
        """Call the closer method of the logger."""
        # In case multiple handlers are attached to the logger make sure they
        # are all closed.
        for handler in self.logger.handlers:
            handler.close()


class CustomRotatingFileLogger(CustomLogger):
    """Subclass CustomLogger to provide a rotating file logger.

    The rotation of log file is enabled by default.

    Usage:
        >>> import sys
        >>> sys.stderr = CustomRotatingFileLogger(filepath='/foo.log')

    Arguments:
        filepath (str) : file path of the log file
        maxbytes (int) : log file is rotated when it grows bigger than maxbytes
        backupcount (int): maximum rotated log file to keep.

    Notice:
        If maxbytes is zero, rollover never occurs and we may fill up the disk.
        An external program (logrotate) must not rotate the file in this case,
        as the file descriptor for the log file will be changed without us
        knowing this.

    Returns:
        A logger object.

    """

    def __init__(self, filepath, *, maxbytes=10485, backupcount=8):
        """Create a logging.Logger class with extended functionality."""
        handler = logging.handlers.RotatingFileHandler(filepath,
                                                       maxBytes=maxbytes,
                                                       backupCount=backupcount)
        super().__init__(handler=handler)


class CustomUdpLogger(CustomLogger):
    """Subclass CustomLogger to provide a UDP logger.

    Usage:
        >>> import sys
        >>> sys.stderr = CustomUdpLogger(server='127.0.0.1')

    Arguments
        server (str): UDP server name or IP address.
        port (int): Port number.

    Returns:
        A logger object.

    """

    def __init__(self, server='127.0.0.1', port=514):
        """Create a logging.Logger class with extended functionality."""
        handler = logging.handlers.SysLogHandler((server, port))
        super().__init__(handler=handler)


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Customize the Json Formatter."""

    def process_log_record(self, log_record):
        """Add customer record keys and rename threadName key."""
        log_record["version"] = __version__
        log_record["program"] = PROGRAM_NAME
        log_record["service_name"] = log_record.pop('threadName', None)
        # return jsonlogger.JsonFormatter.process_log_record(self, log_record)

        return log_record
