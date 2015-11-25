# pylint: disable=superfluous-parens
#

"""
A library which provides the HealthChecker class.
"""

import subprocess
import sys
import time
from queue import Queue
import shlex

from anycast_healthchecker.servicecheck import ServiceCheck
from anycast_healthchecker.utils import (OPTIONS_TYPE,
                                         get_ip_prefixes_from_bird,
                                         ip_prefixes_without_config)


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

        self.log.info('Initialize healthchecker')

    def _update_bird_conf_file(self, operation):
        """Updates BIRD configuration.

        Adds/removes entries from a list and updates generation time stamp.
        Main program will exit if configuration file cant be read/written.

        Arguments:
            operation (obj): Either an AddOperation or DeleteOperation object

        Returns:
            True if BIRD configuration was updated otherwise False.

        """
        conf_updated = False
        prefixes = []
        comment = ("# {} is a dummy IP Prefix. It should NOT be used and "
                   "REMOVED from the constant.".format(self.dummy_ip_prefix))

        try:
            prefixes = get_ip_prefixes_from_bird(self.bird_conf_file, die=False)
        except OSError as err:
            msg = "Failed to open bird configuration, {e}".format(e=err)
            self.log.error(msg, priority=80)
            self.log.critical('This is a FATAL error, exiting', priority=80)
            sys.exit(1)

        if not prefixes:
            msg = "Found empty bird configuration:{f}".format(
                f=self.bird_conf_file)
            self.log.error(msg, priority=80)
            self.log.critical('This is a FATAL error, exiting', priority=80)
            sys.exit(1)

        if self.dummy_ip_prefix not in prefixes:
            msg = ("Dummy IP prefix {i} wasn't found in bird configuration, "
                   "adding it. This shouldn't have happened!").format(
                       i=self.dummy_ip_prefix)
            self.log.warning(msg, priority=20)
            prefixes.insert(0, self.dummy_ip_prefix)
            conf_updated = True

        # Remove IP prefixes for which we don't have a configuration for them.
        notconfigured_ip_prefixes = ip_prefixes_without_config(prefixes,
                                                               self.config,
                                                               self.services)
        if notconfigured_ip_prefixes:
            msg = ("found {i} IP prefixes in Bird configuration but we aren't "
                   "configured to run health checks on them. Either someone "
                   "modified the configuration manually or something went "
                   "horrible wrong. Thus, we remove them from Bird "
                   "configuration").format(
                       i=','.join(notconfigured_ip_prefixes))
            self.log.warning(msg, priority=20)
            # This is faster than using lambda and filter.
            # NOTE: We don't use remove method as we want to remove more than
            # occurrences of the IP prefixes without check.
            prefixes[:] = (ip for ip in prefixes
                           if ip not in notconfigured_ip_prefixes)
            conf_updated = True

        # Update the list of IP prefixes based on the status of health check.
        if operation.update(prefixes):
            conf_updated = True

        if not conf_updated:
            self.log.info('No updates for bird configuration')
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
                bird_conf.write(',\n'.join(map(lambda p: ' '*8 + p, prefixes)))
                bird_conf.write("\n{spaces}];\n".format(spaces=4 * ' '))
                bird_conf.truncate()
                self.log.info('Bird configuration is updated')
        except OSError as error:
            self.log.critical('Failed to update bird configuration',
                              priority=80)
            self.log.critical(error, priority=80)
            self.log.critical('This is a FATAL error, exiting', priority=80)
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
        _cmd = shlex.split(self.config['daemon']['bird_reconfigure_cmd'])
        try:
            _output = subprocess.check_output(
                _cmd,
                timeout=2,
                stderr=subprocess.STDOUT,
                universal_newlines=True)
        except subprocess.TimeoutExpired:
            self.log.error("Reloading bird timed out", priority=80)
            return
        except subprocess.CalledProcessError as error:
            # birdc returns 0 even when it fails due to invalid config,
            # but it returns 1 when BIRD is down.
            msg = ("Reloading BIRD failed, most likely BIRD daemon is down"
                   ":{e}").format(e=error.output)
            self.log.error(msg, priority=80)
            return
        except FileNotFoundError as error:
            msg = "Reloading BIRD failed with: {e}".format(e=error)
            self.log.error(msg, priority=80)
            return

        # 'Reconfigured' string will be in the output if and only if conf is
        # valid.
        if 'Reconfigured' in _output:
            self.log.info('Reloaded BIRD daemon')
        else:
            # We will end up here only if we generated an invalid conf
            # or someone broke bird.conf.
            msg = ("Reloading BIRD returned error, most likely we generated "
                   "an invalid configuration file or Bird configuration in "
                   "general is broken:{e}").format(e=_output)
            self.log.error(msg, priority=80)

    def run(self):
        """Lunches checks and triggers updates on BIRD configuration."""

        # Lunch a thread for each configuration
        msg = "Going to lunch {n} threads".format(n=len(self.services))
        self.log.info(msg)
        for service in self.services:
            msg = "Lunching thread for {n}".format(n=service)
            self.log.debug(msg)
            _config = {}
            for option, getter in OPTIONS_TYPE.items():
                _config[option] = getattr(self.config, getter)(service, option)
            _thread = ServiceCheck(
                service,
                _config,
                self.action,
                self.log)
            _thread.start()

        # Stay running until we are stopped
        while True:
            # Fetch items from action queue
            operation = self.action.get(block=True)
            msg = ("Returned an item from the queue for {n} with IP prefix {i}"
                   " and action to {o} Bird configuration").format(
                       n=operation.name,
                       i=operation.ip_prefix,
                       o=operation)
            self.log.info(msg)
            bird_updated = self._update_bird_conf_file(operation)
            self.action.task_done()
            if bird_updated:
                self._reload_bird()

    def catch_signal(self, signum, frame):
        """A signal catcher.

        Arguments:
            signum (int): The signal number.
            frame (str): The stack frame at the time the signal was received.
        """
        self.log.info("Received {n} signal".format(n=signum), priority=80)
        self.log.info('Going down', priority=80)
        sys.exit(0)
