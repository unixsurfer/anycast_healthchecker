# pylint: disable=superfluous-parens
# pylint: disable=too-many-arguments

"""
A library which provides the HealthChecker class.
"""
import os
import subprocess
import sys
import time
import datetime
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

        self.log.info('initialize healthchecker')

    def _write_temp_bird_conf(self, prefixes):
        """Writes in a temporary file the list of IP-Prefixes

        A failure to create and write the temporary file will exit main
        program.

        Arguments:
            prefixes (list): The list of IP-Prefixes to write
        Returns:
            The filename of the temporary file
        """
        comment = ("# {i} is a dummy IP Prefix. It should NOT be used and "
                   "REMOVED from the constant.".format(i=self.dummy_ip_prefix))

        # the temporary file must be on the same filesystem as the bird config
        # as we use os.rename to perform an atomic update on the bird config.
        # Thus, we create it in the same directory that bird config is stored.
        tm_file = os.path.dirname(self.bird_conf_file) + '/' + str(time.time())
        self.log.debug("going to write to {f}".format(f=tm_file),
                       json_blob=False)
        try:
            with open(tm_file, 'w') as tmpf:
                tmpf.write("# Generated {t} by anycast-healthchecker (pid={p})"
                           "\n".format(t=datetime.datetime.now(),
                                       p=os.getpid()))
                tmpf.write("{c}\n".format(c=comment))
                tmpf.write("define {n} =\n".format(n=self.bird_constant_name))
                tmpf.write("{s}[\n".format(s=4 * ' '))
                # all entries of the array constant need a trailing comma
                # except the last one. A single element array doesn't need
                # the trailing comma.
                tmpf.write(',\n'.join([' '*8 + n for n in prefixes]))
                tmpf.write("\n{s}];\n".format(s=4 * ' '))
        except OSError as error:
            msg = ("failed to write temporary file {f}: {e}. This is a FATAL "
                   "error, this exiting main program".format(f=tm_file,
                                                             e=error))
            self.log.critical(msg, priority=80)
            sys.exit(1)
        else:
            return tm_file

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

        try:
            prefixes = get_ip_prefixes_from_bird(self.bird_conf_file,
                                                 die=False)
        except OSError as error:
            msg = ('failed to open Bird configuration {e}, this is a FATAL'
                   'error, thus exiting main program').format(e=error)
            self.log.error(msg, priority=80)
            sys.exit(1)

        if not prefixes:
            msg = ("found empty bird configuration:{f}, this is a FATAL"
                   "error, thus exiting main program").format(
                       f=self.bird_conf_file)
            self.log.error(msg, priority=80)
            sys.exit(1)

        if self.dummy_ip_prefix not in prefixes:
            msg = ("dummy IP prefix {i} wasn't found in bird configuration, "
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
            self.log.info('no updates for bird configuration')
            return conf_updated

        # some IP prefixes are either removed or added, create
        # configuration with new data.
        tempname = self._write_temp_bird_conf(prefixes)
        try:
            os.rename(tempname, self.bird_conf_file)
        except OSError as error:
            msg = ('failed to create Bird configuration {e}, this is a FATAL '
                   'error, thus exiting main program').format(e=error)
            self.log.critical(msg, priority=80)
            sys.exit(1)
        else:
            self.log.info('Bird configuration is updated')

        # dummy_ip_prefix is always there
        if len(prefixes) == 1:
            self.log.warning("Bird configuration doesn't have IP prefixes for "
                             "any of the services we monitor! It means local "
                             "node doesn't receive any traffic", priority=80)

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
            self.log.error("reloading bird timed out", priority=80)
            return
        except subprocess.CalledProcessError as error:
            # birdc returns 0 even when it fails due to invalid config,
            # but it returns 1 when BIRD is down.
            msg = ("reloading BIRD failed, most likely BIRD daemon is down"
                   ":{e}").format(e=error.output.strip())
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
            msg = ("reloading BIRD returned error, most likely we generated "
                   "an invalid configuration file or Bird configuration in "
                   "general is broken:{e}").format(e=_output)
            self.log.error(msg, priority=80)

    def run(self):
        """Lunches checks and triggers updates on BIRD configuration."""

        # Lunch a thread for each configuration
        msg = "going to lunch {n} threads".format(n=len(self.services))
        self.log.info(msg)
        for service in self.services:
            msg = "lunching thread for {n}".format(n=service)
            self.log.debug(msg, json_blob=False)
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
            msg = ("returned an item from the queue for {n} with IP prefix {i}"
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
        self.log.info("received {n} signal {f}".format(n=signum,
                                                       f=frame), priority=80)
        self.log.info('going down', priority=50)
        sys.exit(0)
