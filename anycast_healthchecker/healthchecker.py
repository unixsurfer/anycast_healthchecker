# pylint: disable=superfluous-parens
#

"""
A library which provides the HealthChecker class.
"""

import subprocess
import os
import glob
import sys
import time
from threading import Event
from queue import Queue, Empty
import re

from anycast_healthchecker.servicecheck import ServiceCheck


class HealthChecker(object):
    """Lunches service checkers and triggers a reconfiguration on BIRD.

    This class should be instantiated once and daemonized.

    Loads configuration files which have extension 'json' and are valid
    JSON documents. Each file defines a service check with some attributes
    and is being lunched as an individual thread.
    Here is example configuration:
    {
        "name": "graphite-api.foo.com",
        "check_cmd": "absolute path of cmd which returns exit code 0 or 1",
        "check_interval": 10,
        "check_timeout": 5,
        "check_rise": 3,
        "check_fail": 2,
        "check_disabled": false,
        "on_disabled": "withdraw",
        "ip_prefix": "10.189.200.1/32"
    }

    It uses also a Event object to send a stop event to all threads when
    SIGTERM and SIGHUP are sent. It uses a queue as a store for IP_PREFIXes
    to be removed from and added to BIRD configuration.
    The BIRD configuration file that is being modified, defines a
    constant of IP_PREFIXes for which routes are allowed to be announced
    via routing protocols. When an IP_PREFIX is removed from that
    constant, BIRD daemon withdraws the route associated that IP_PREFIX.

    Arguments:
        log(logger): A logger to log messages.

        cfg_dir ('str'): The absolute path of a configuration directory
        which contains configuration files for each check.

        bird_conf_file('str'): The absolute path of file which contains
        the definition of constant used by BIRD daemon.

        bird_constant_name('str'): The constant name used in the bird
        configuration.

        dummy_prefix('str'): The dummy IP prefix which must be always present
        in bird_constant_name and never removed.

        stop_event(Queue obj): A queue to communicate with stop events to
        threads.

        action(Queue obj): A queue of ip_prefixes and their action to
        take after health of a check is determined. An item is a tuple of
        3 elements:
            1st: The name of the thread.
            2nd: ip_prefix.
            3nd: Action to take, either 'add' or 'del'.

    Methods:
        run(): Lunches checks and updates bird configuration based on
        the result of the check.
        catch_signal(signum, frame): Catches signals and sends stop events
        to all threads, and then exits main program.

    """
    def __init__(self,
                 log,
                 cfg_dir,
                 bird_conf_file,
                 bird_constant_name,
                 dummy_ip_prefix):
        self.log = log
        self.cfg_dir = cfg_dir
        self.bird_conf_file = bird_conf_file
        self.dummy_ip_prefix = dummy_ip_prefix
        self.bird_constant_name = bird_constant_name
        self.stop_event = Event()
        self.action = Queue()

        self.log.debug("Initialize HealthChecker")

    def _get_config_files(self):
        """Retrieves the absolute file path of configuration files.

        Returns:
            A list of absolute file paths.
        """
        _file_names = []
        self.log.debug("Loading files from {}".format(self.cfg_dir))
        for name in glob.glob(os.path.join(self.cfg_dir, '*.json')):
            self.log.debug("Found {} configuration".format(name))
            _file_names.append(name)

        if not _file_names:
            self.log.warning('No configuration files were found!')

        return _file_names

    def _update_bird_prefix_conf(self, health_action):
        """Updates BIRD configuration.

        It adds/removes entries from a list and updates generation timestamp.
        Main program will exit if configuration file cant be read/written.

        Arguments:
            health_action (tuple): A 3 element tuple:
            1st: The name of the thread (str)
            2nd: ip_prefix (str)
            3nd: Action to take, either 'add' or 'del' (str)

        Returns:
            True if BIRD configuration was updated otherwise False.

        """
        conf_updated = False
        prefixes = []
        name = health_action[0]
        ip_prefix = health_action[1]
        action = health_action[2]
        comment = ("# {} is a dummy IP Prefix. It should NOT be used and "
                   "REMOVED from the constant.".format(self.dummy_ip_prefix))

        # matches IPs with a trailing comma or not
        # TODO: Do I need to if it a real valid IP
        pat = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,},?')
        try:
            bird_conf = open(self.bird_conf_file, 'r+')
            lines = bird_conf.read()
            for line in lines.splitlines():
                line = line.strip()
                if pat.match(line):
                    prefixes.append(line.rstrip(','))
        except (IOError, OSError) as error:
            self.log.critical("Failed to open bird configuration")
            self.log.critical(error)
            self.log.critical("This is a FATAL error, exiting")
            sys.exit(1)

        if not prefixes:
            self.log.critical("Found empty bird configuration:{}".format(
                self.bird_conf_file))
            self.log.critical("This is a FATAL error, exiting")
            sys.exit(1)

        if self.dummy_ip_prefix not in prefixes:
            self.log.warning("Dummy IP Prefix {} wasn't found in bird "
                             "configuration, adding it. This shouldn't have "
                             "happened!".format(self.dummy_ip_prefix))
            prefixes.insert(0, self.dummy_ip_prefix)
            conf_updated = True

        if action == 'del' and ip_prefix in prefixes:
            self.log.info("Withdrawing {} for {}".format(ip_prefix, name))
            prefixes.remove(ip_prefix)
            conf_updated = True
        elif action == 'add' and ip_prefix not in prefixes:
            self.log.info("Announcing {} for {}".format(ip_prefix, name))
            prefixes.append(ip_prefix)
            conf_updated = True

        if not conf_updated:
            bird_conf.close()
            self.log.info("No updates for bird configuration")
            return conf_updated

        # OK some IP_PREFIXes are either removed or added,
        # go and truncate configuration with new data.
        bird_conf.seek(0)
        bird_conf.write("# Generated {} by anycast-healthchecker\n".format(
            time.ctime()))
        bird_conf.write("{}\n".format(comment))
        bird_conf.write("define {} =\n".format(self.bird_constant_name))
        bird_conf.write("{}[\n".format(4 * ' '))
        # all entries of the array constant need a trailing comma
        # except the last one. A single element array doesn't need the
        # trailing comma.
        for prefix in prefixes[:-1]:
            bird_conf.write("{}{},\n".format(8 * ' ', prefix))
        bird_conf.write("{}{}\n".format(8 * ' ', prefixes[len(prefixes) - 1]))
        bird_conf.write("{}];\n".format(4 * ' '))
        bird_conf.truncate()
        bird_conf.close()
        self.log.info("Bird configuration is updated")

        return conf_updated

    def _reload_bird(self):
        """Reloads BIRD daemon.

        It uses 'birdc configure' to reload BIRD. Some useful information
        on how birdc works:
            -- It returns a non-zero exit code only when it can't access
            BIRD via the control socket (/var/run/bird.ctl). This happens
            when BIRD daemon is down or when the caller of birdc doesn't
            have access to the control socket.
            -- It returns zero exit code when reload fails due to invalid
            config, thus we catch this case by looking at the output and
            not at the exit code.
            -- It returns zero exit code when reload was successful.
            -- It should never timeout, if it does then it is a bug.

        """
        _cmd = ['sudo', '/usr/sbin/birdc', 'configure']
        try:
            _output = subprocess.check_output(
                _cmd,
                timeout=2,
                stderr=subprocess.STDOUT,
                universal_newlines=True)
        except subprocess.TimeoutExpired:
            self.log.error("Reloading bird timed out")
            return
        except subprocess.CalledProcessError as error:
            # birdc returns 0 even when it fails due to invalid config,
            # but it returns 1 when BIRD is down.
            self.log.error(("Reloading BIRD failed, most likely BIRD daemon"
                            " is down:{}").format(error.output))
            return

        # 'Reconfigured' string will be in the output if and only if conf is
        # valid.
        if 'Reconfigured' in _output:
            self.log.info("Reloaded BIRD daemon")
        else:
            # We will end up here only if we generated an invalid conf
            # or someone broke bird.conf.
            self.log.error(("Reloading BIRD returned error, most likely we "
                            "generated an invalid conf or bird.conf is broken"
                            ":{}").format(_output))

    def run(self):
        """Lunches checks and triggers updates on BIRD configuration."""
        self.log.info("Lunching checks")
        _workers = []
        files = self._get_config_files()

        # Lunch a thread for each configuration
        self.log.info("Going to lunch {} threads".format(len(files)))
        for config_file in files:
            _thread = ServiceCheck(
                config_file,
                self.stop_event,
                self.action,
                self.log)
            _thread.start()
            _workers.append(_thread)

        # Stay running until we receive a stop event
        while not self.stop_event.is_set():
            try:
                # Fetch items from action queue
                health_action = self.action.get(1)
                self.log.info(("Returned an item from the queue for {} with "
                               "IP_PREFIX {} and action to {} from Bird "
                               "configuration").format(health_action[0],
                                                       health_action[1],
                                                       health_action[2]))

                bird_updated = self._update_bird_prefix_conf(health_action)
                self.action.task_done()
                if bird_updated:
                    self._reload_bird()
            except Empty:
                # Just keep trying to fetch item
                continue

        for _thread in _workers:
            _thread.join()

    def catch_signal(self, signum, frame):
        """A signal catcher.

        Upon catching a signal send stop event to all threads, wait a bit
        and then exit the main program.

        Arguments:
            signum (int): The signal number.
            frame (str): The stack frame at the time the signal was received.
        """
        self.log.info("Received {} signal".format(signum))
        self.stop_event.set()
        self.log.info("Sent stop event to all threads")
        time.sleep(2)
        self.log.info("Going down")
        sys.exit(0)
