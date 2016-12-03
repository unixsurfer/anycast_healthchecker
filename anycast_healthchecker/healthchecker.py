# pylint: disable=too-many-arguments

"""
A library which provides the HealthChecker class.
"""
import os
import sys
from queue import Queue

from anycast_healthchecker.servicecheck import ServiceCheck
from anycast_healthchecker.utils import (SERVICE_OPTIONS_TYPE,
                                         get_ip_prefixes_from_bird,
                                         get_ip_prefixes_from_config,
                                         reconfigure_bird,
                                         write_temp_bird_conf,
                                         archive_bird_conf)


class HealthChecker(object):
    """Lunches service checks and triggers a reconfiguration on BIRD daemon.

    This class should be instantiated once and daemonized.

    It uses a queue as a store for IP prefixes to be removed from and added to
    BIRD configuration file.

    Arguments:
        log(logger obj): A logger to log messages.

        config(configparger obj): A configparser object with the configuration

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
    def __init__(self, log, config, bird_configuration):
        self.log = log
        self.config = config
        self.action = Queue()
        self.bird_configuration = bird_configuration
        self.log.debug(self.bird_configuration)

        # A list of service of checks
        self.services = config.sections()
        self.services.remove('daemon')

        # Holds IP prefixes per IP version for which we have a service check
        self.ip_prefixes = {}
        for ip_version in self.bird_configuration:
            _ip_prefixes = get_ip_prefixes_from_config(
                self.config,
                self.services,
                ip_version)
            _ip_prefixes.add(
                self.bird_configuration[ip_version]['dummy_ip_prefix'])
            self.ip_prefixes[ip_version] = _ip_prefixes

        self.log.info('initialize healthchecker')

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
        ip_version = operation.ip_version
        config_file = self.bird_configuration[ip_version]['config_file']
        variable_name = self.bird_configuration[ip_version]['variable_name']
        changes_counter =\
            self.bird_configuration[ip_version]['changes_counter']
        dummy_ip_prefix =\
            self.bird_configuration[ip_version]['dummy_ip_prefix']

        try:
            prefixes = get_ip_prefixes_from_bird(config_file)
        except OSError as error:
            msg = ("failed to open Bird configuration {e}, this is a FATAL "
                   "error, thus exiting main program"
                   .format(e=error))
            self.log.error(msg, priority=80)
            sys.exit(1)

        if not prefixes:
            msg = ("found empty bird configuration:{f}, this is a FATAL "
                   "error, thus exiting main program"
                   .format(f=config_file))
            self.log.error(msg, priority=80)
            sys.exit(1)

        if dummy_ip_prefix not in prefixes:
            msg = ("dummy IP prefix {i} wasn't found in bird configuration, "
                   "adding it. This shouldn't have happened!"
                   .format(i=dummy_ip_prefix))
            self.log.warning(msg, priority=20)
            prefixes.insert(0, dummy_ip_prefix)
            conf_updated = True

        ip_prefixes_without_check = set(prefixes).difference(
            self.ip_prefixes[ip_version])
        if ip_prefixes_without_check:
            msg = ("found {i} IP prefixes in Bird configuration but we aren't "
                   "configured to run health checks on them. Either someone "
                   "modified the configuration manually or something went "
                   "horrible wrong. We remove them from Bird configuration"
                   .format(i=','.join(ip_prefixes_without_check)))
            self.log.warning(msg, priority=20)
            # This is faster than using lambda and filter.
            # NOTE: We don't use remove method as we want to remove more than
            # occurrences of the IP prefixes without check.
            prefixes[:] = (ip for ip in prefixes
                           if ip not in ip_prefixes_without_check)
            conf_updated = True

        # Update the list of IP prefixes based on the status of health check.
        if operation.update(prefixes):
            conf_updated = True

        if not conf_updated:
            self.log.info('no updates for bird configuration')
            return conf_updated

        if self.bird_configuration[ip_version]['keep_changes']:
            archive_bird_conf(self.log, config_file, changes_counter)

        # some IP prefixes are either removed or added, create
        # configuration with new data.
        tempname = write_temp_bird_conf(
            self.log,
            dummy_ip_prefix,
            config_file,
            variable_name,
            prefixes
        )
        try:
            os.rename(tempname, config_file)
        except OSError as error:
            msg = ('failed to create Bird configuration {e}, this is a FATAL '
                   'error, thus exiting main program'
                   .format(e=error))
            self.log.critical(msg, priority=80)
            sys.exit(1)
        else:
            self.log.info("Bird configuration for IPv{v} is updated"
                          .format(v=ip_version))

        # dummy_ip_prefix is always there
        if len(prefixes) == 1:
            self.log.warning("Bird configuration doesn't have IP prefixes for "
                             "any of the services we monitor! It means local "
                             "node doesn't receive any traffic", priority=80)

        return conf_updated

    def run(self):
        """Lunches checks and triggers updates on BIRD configuration."""

        # Lunch a thread for each configuration
        if not self.services:
            self.log.warning("no service checks are configured")
        else:
            msg = "going to lunch {n} threads".format(n=len(self.services))
            self.log.info(msg)
            for service in self.services:
                msg = "lunching thread for {n}".format(n=service)
                self.log.debug(msg, json_blob=False)
                _config = {}
                for option, getter in SERVICE_OPTIONS_TYPE.items():
                    _config[option] = getattr(self.config, getter)(service,
                                                                   option)
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
                   " and action to {o} Bird configuration"
                   .format(n=operation.name,
                           i=operation.ip_prefix,
                           o=operation))
            self.log.info(msg)
            bird_updated = self._update_bird_conf_file(operation)
            self.action.task_done()
            if bird_updated:
                ip_version = operation.ip_version
                cmd = self.bird_configuration[ip_version]['reconfigure_cmd']
                reconfigure_bird(self.log, cmd)

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
