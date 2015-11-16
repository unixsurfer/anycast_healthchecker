# pylint: disable=superfluous-parens
#

"""
A library which provides the ServiceCheck class.
"""

import subprocess
import time
from threading import Thread
import shlex

from anycast_healthchecker.utils import AddOperation, DeleteOperation


class ServiceCheck(Thread):
    """Handles a check for a service.

    Arguments:
        config_file (str): The absolute path of the configuration file for the
        service check.
        action (Queue obj): A queue object to put health actions.
        log (logger obj): A logger object to use.

    Methods:
        run(): Run method of the thread.
    """
    def __init__(self, service, config, action, log):
        """Set the name of thread to be the name of the service."""
        super(ServiceCheck, self).__init__()
        self.name = service
        self.daemon = True
        self.config = config
        self.action = action
        self.log = log
        self.log.info("Loading check for {}".format(self.name))

    def _run_check(self):
        """Executes a check command.

        Returns:
            True if the exit code of the command was 0 otherwise False.
        """
        cmd = shlex.split(self.config['check_cmd'])
        self.log.info("Running {}".format(' '.join(cmd)))
        proc = subprocess.Popen(cmd,
                                stdin=None,
                                stdout=None,
                                stderr=None,
                                close_fds=True)

        start_time = time.time()
        try:
            proc.wait(self.config['check_timeout'])
        except subprocess.TimeoutExpired:
            self.log.error("Check timed out")
            if proc.poll() is None:
                proc.kill()
            return False
        else:
            self.log.debug("Check duration {t:.3f}ms".format(
                t=(time.time() - start_time) * 1000))
            return proc.returncode == 0

    def _ip_assigned(self):
        """Checks if IP prefix is assigned to loopback interface.

        Returns:
            True if IP prefix found assigned otherwise False.
        """
        cmd = [
            '/sbin/ip',
            'address',
            'show',
            'dev',
            "{}".format(self.config['interface']),
            'to',
            "{}".format(self.config['ip_prefix']),
        ]

        self.log.debug("running {}".format(' '.join(cmd)))
        try:
            out = subprocess.check_output(
                cmd,
                universal_newlines=True,
                timeout=1)
        except subprocess.CalledProcessError as error:
            self.log.error("Error checking IP-PREFIX {} {}".format(
                cmd,
                error.output))
            # Because it is unlikely to ever get an error I return True
            return True
        except subprocess.TimeoutExpired:
            self.log.error("Timeout running {}".format(' '.join(cmd)))
            # Because it is unlikely to ever get a timeout I return True
            return True
        else:
            if self.config['ip_prefix'] in out:
                self.log.debug("{} assigned to loopback interface".format(
                    self.config['ip_prefix']))
                return True
            else:
                self.log.debug("{} NOT assigned to loopback interface".format(
                    self.config['ip_prefix']))
                return False

        self.log.debug("I shouldn't land here!, it is a BUG")

        return False

    def _check_disabled(self):
        """Checks if service check is disabled.

        It logs a message if check is disabled and it also adds an item
        to the action queue based on 'on_disabled' setting.

        Returns:
            True if check is disabled otherwise False.
        """
        if (self.config['check_disabled']
                and self.config['on_disabled'] == 'withdraw'):
            self.log.info("Check is disabled and ip_prefix will be withdrawn")
            operation = DeleteOperation(name=self.name,
                                        ip_prefix=self.config['ip_prefix'],
                                        log=self.log)
            self.action.put(operation)
            self.log.info("{} in queue".format(self.config['ip_prefix']))
            self.log.info("Check is now permanently disabled")
            return True
        elif (self.config['check_disabled']
              and self.config['on_disabled'] == 'advertise'):
            self.log.info("Check is disabled, ip_prefix wont be withdrawn")
            operation = AddOperation(name=self.name,
                                     ip_prefix=self.config['ip_prefix'],
                                     log=self.log)
            self.action.put(operation)
            self.log.info("{} in queue".format(self.config['ip_prefix']))
            self.log.info("Check is now permanently disabled")
            return True

        return False

    def run(self):
        """Discovers the health of a service.

        Runs until it is being killed from main program and is responsible to
        put an item into the queue based on the status of the health check.
        The status of service is consider UP after a number of consecutive
        successful health checks, in that case it asks main program to add the
        IP prefix associated with service to BIRD configuration, otherwise ask
        for a removal.
        Rise and fail options prevent unnecessary configuration changes when
        check is flapping.
        """
        up_cnt = 0
        down_cnt = 0
        # The current established state of the service check, it can be
        # either UP or DOWN but only after a number of consecutive successful
        # or failure health checks.
        check_state = 'Unknown'

        for key, value in self.config.items():
            self.log.debug("{}={}:{}".format(key, value, type(value)))

        # Service check will abort if it is disabled.
        if self._check_disabled():
            return

        # Go in a loop until we are told to stop
        while True:

            if not self._ip_assigned():
                up_cnt = 0
                self.log.info(("Status DOWN because {0} isn't assigned to"
                               " to loopback interface. {0} prefix isn't"
                               " removed from BIRD configuration as direct"
                               " protocol in BIRD has already withdrawn the"
                               " route for that prefix. In nutshell traffic"
                               " is NOT routed anymore to this"
                               " node").format(self.config['ip_prefix']))
                if check_state != 'DOWN':
                    check_state = 'DOWN'
            elif self._run_check():
                if up_cnt == (self.config['check_rise'] - 1):
                    self.log.info("Status UP")
                    # Service exceeded all consecutive checks. Set its state
                    # accordingly and put an item in queue. But to it only if
                    # previous state was different, to catch unnecessary bird
                    # reloads when a service flaps between states.
                    if check_state != 'UP':
                        check_state = 'UP'
                        operation = AddOperation(
                            name=self.name,
                            ip_prefix=self.config['ip_prefix'],
                            log=self.log)
                        self.action.put(operation)
                        self.log.info(
                            "Queued {}".format(self.config['ip_prefix']))
                elif up_cnt < self.config['check_rise']:
                    up_cnt += 1
                    self.log.info("Going UP {}".format(up_cnt))
                else:
                    self.log.error("up_cnt higher, it's a BUG! {}".format(
                        up_cnt))
                down_cnt = 0
            else:
                if down_cnt == (self.config['check_fail'] - 1):
                    self.log.info("Status DOWN")
                    # Service exceeded all consecutive checks.
                    # Set its state accordingly and put an item in queue.
                    # But to it only if previous state was different, to catch
                    # unnecessary bird reloads when a service flaps between states
                    if check_state != 'DOWN':
                        check_state = 'DOWN'
                        operation = DeleteOperation(
                            name=self.name,
                            ip_prefix=self.config['ip_prefix'],
                            log=self.log)
                        self.action.put(operation)
                        self.log.info(
                            "Queued {}".format(self.config['ip_prefix']))
                elif down_cnt < self.config['check_fail']:
                    down_cnt += 1
                    self.log.info("Going down {}".format(down_cnt))
                else:
                    self.log.error("down_cnt higher, it's a BUG! {}".format(
                        down_cnt))
                up_cnt = 0
            self.log.debug("Sleeping {} secs".format(
                self.config['check_interval']))
            time.sleep(self.config['check_interval'])
