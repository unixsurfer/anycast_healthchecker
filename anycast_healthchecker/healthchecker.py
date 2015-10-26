# pylint: disable=superfluous-parens
#

"""
A library which provides the HealthChecker class.
"""

import subprocess
import sys
import time
from queue import Queue, Empty

from anycast_healthchecker.servicecheck import ServiceCheck
from anycast_healthchecker.utils import OPTIONS_TYPE, get_ip_prefixes_from_bird


class HealthChecker(object):
    """Lunches service checks and triggers a reconfiguration on BIRD daemon.

    This class should be instantiated once and daemonized.

    It uses a queue as a store for IP prefixes to be removed from and added to
    BIRD configuration file.

    Arguments:
        log(logger obj): A logger to log messages.

        config(configparger obj): A configparser object with the configuration

        bird_conf_file('str'): The absolute path of file which contains the
        definition of constant used by BIRD daemon to store IP prefixes for
        which routes are allowed to be advertised

        bird_constant_name('str'): The constant name used in the BIRD daemon
        configuration.

        dummy_prefix('str'): A dummy IP prefix which must be always present
        in bird_constant_name and it should never be removed from it.

        action(Queue obj): A queue of IP prefixes and their action to be taken
        based on the state of health check. An item is a tuple of 3 elements:
            1st: name of the thread.
            2nd: IP prefix.
            3nd: Action to take, either 'add' or 'del'.

    Methods:
        run(): Lunches checks and updates BIRD configuration based on
        the result of the check.
        catch_signal(signum, frame): Catches signals
    """
    def __init__(self,
                 log,
                 config,
                 bird_conf_file,
                 bird_constant_name,
                 dummy_ip_prefix):
        self.log = log
        self.config = config
        self.bird_conf_file = bird_conf_file
        self.dummy_ip_prefix = dummy_ip_prefix
        self.bird_constant_name = bird_constant_name
        self.action = Queue()

        # A list of service of checks
        self.services = config.sections()
        self.services.remove('daemon')

        self.log.debug("Initialize healthchecker")

    def _update_bird_prefix_conf(self, health_action):
        """Updates BIRD configuration.

        Adds/removes entries from a list and updates generation time stamp.
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

        try:
            prefixes = get_ip_prefixes_from_bird(self.bird_conf_file, die=False)
        except OSError as err:
            self.log.error("Failed to open bird configuration, {}".format(err))
            self.log.critical("This is a FATAL error, exiting")
            sys.exit(1)

        if not prefixes:
            self.log.error("Found empty bird configuration:{}".format(
                self.bird_conf_file))
            self.log.critical("This is a FATAL error, exiting")
            sys.exit(1)

        if self.dummy_ip_prefix not in prefixes:
            self.log.warning("Dummy IP prefix {} wasn't found in bird "
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
            self.log.info("No updates for bird configuration")
            return conf_updated

        # some IP prefixes are either removed or added, truncate configuration
        # with new data.
        try:
            with open(self.bird_conf_file, 'r+') as bird_conf:
                bird_conf.seek(0)
                bird_conf.write("# Generated {time} by anycast-healthchecker"
                                "\n".format(time=time.ctime()))
                bird_conf.write("{}\n".format(comment))
                bird_conf.write("define {} =\n".format(self.bird_constant_name))
                bird_conf.write("{}[\n".format(4 * ' '))
                # all entries of the array constant need a trailing comma
                # except the last one. A single element array doesn't need the
                # trailing comma.
                for prefix in prefixes[:-1]:
                    bird_conf.write("{}{},\n".format(8 * ' ', prefix))
                bird_conf.write("{}{}\n".format(8 * ' ',
                                                prefixes[len(prefixes) - 1]))
                bird_conf.write("{}];\n".format(4 * ' '))
                bird_conf.truncate()
                bird_conf.close()
                self.log.info("Bird configuration is updated")
        except OSError as error:
            self.log.critical("Failed to update bird configuration")
            self.log.critical(error)
            self.log.critical("This is a FATAL error, exiting")
            sys.exit(1)

        return conf_updated

    def _reload_bird(self):
        """Reloads BIRD daemon.

        Runs 'birdc configure' to reload BIRD. Some useful information on how
        birdc tool works:
            -- Returns a non-zero exit code only when it can't access BIRD
            daemon via the control socket (/var/run/bird.ctl).
            This happens when BIRD daemon is either down or when the caller of
            birdc doesn't have access to the control socket.
            -- Returns zero exit code when reload fails due to invalid
            configuration. Thus, we catch this case by looking at the output
            and not at the exit code.
            -- Returns zero exit code when reload was successful.
            -- Should never timeout, if it does then it is a bug.
        """
        _cmd = self.config['daemon']['bird_reconfigure_cmd'].split()
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

        # Lunch a thread for each configuration
        self.log.info("Going to lunch {} threads".format(len(self.services)))
        for service in self.services:
            self.log.debug("Lunching thread for {}".format(service))
            _config = {}
            for option, getter in OPTIONS_TYPE.items():
                _config[option] = getattr(self.config, getter)(service, option)
            _thread = ServiceCheck(
                service,
                _config,
                self.action,
                self.log)
            _thread.start()
            _workers.append(_thread)

        # Stay running until we are stopped
        while True:
            try:
                # Fetch items from action queue
                health_action = self.action.get(1)
                self.log.info(("Returned an item from the queue for {} with "
                               "IP prefix {} and action to {} from Bird "
                               "configuration").format(health_action[0],
                                                       health_action[1],
                                                       health_action[2]))

                bird_updated = self._update_bird_prefix_conf(health_action)
                self.action.task_done()
                if bird_updated:
                    self._reload_bird()
            except Empty:
                # Just keep trying to fetch items
                continue

        for _thread in _workers:
            _thread.join()

    def catch_signal(self, signum, frame):
        """A signal catcher.

        Arguments:
            signum (int): The signal number.
            frame (str): The stack frame at the time the signal was received.
        """
        self.log.info("Received {} signal".format(signum))
        self.log.info("Going down")
        sys.exit(0)
