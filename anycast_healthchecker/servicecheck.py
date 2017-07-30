# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-instance-attributes
#

"""A library which provides the ServiceCheck class."""

import subprocess
import time
import logging
from threading import Thread
import ipaddress
import shlex

from anycast_healthchecker import PROGRAM_NAME
from anycast_healthchecker.utils import AddOperation, DeleteOperation


class ServiceCheck(Thread):
    """Handle the health checking for a service.

    Arguments:
        service (str): The name of the service to monitor.
        config (dict): A dictionary with the configuration of the service.
        action (Queue obj): A queue object to place actions based on the result
        of the health check.

    Methods:
        run(): Run method of the thread.

    """

    def __init__(self, service, config, action):
        """Set the name of thread to be the name of the service."""
        super(ServiceCheck, self).__init__()
        self.name = service  # Used by Thread()
        self.daemon = True   # Used by Thread()
        self.config = config
        self.action = action
        # sanity check has already been done, so the following *should* not
        # raise an exception
        _ip_prefix = ipaddress.ip_network(self.config['ip_prefix'])
        # NOTE: When subnetmask isn't provided ipaddress module creates an
        # object with a mask of /32 for IPv4 addresses and mask of /128 for
        # IPv6 addresses. As a result the prefix length is either 32 or 128
        # and we can get the IP address by looking at the network_address
        # attribute.
        self.ip_address = str(_ip_prefix.network_address)
        self.prefix_length = _ip_prefix.prefixlen
        self.ip_with_prefixlen = _ip_prefix.with_prefixlen
        self.ip_version = _ip_prefix.version
        self.ip_check_disabled = self.config['ip_check_disabled']
        self.log = logging.getLogger(PROGRAM_NAME)
        self.extra = {
            'ip_address': self.ip_address,
            'prefix_length': self.prefix_length,
            'ip_check_disabled': self.ip_check_disabled,
            'status': 'unknown',
        }
        self.log.info("loading check for %s", self.name, extra=self.extra)

    def _update_status(self, status):
        """Log and update status of the service.

        The severity of the log message depends on the value of status:
            status  : severity
            OK      : info
            DOWN    : critical
            unknown : warning

        Arguments:
            status (str): status to report and

        Returns:
            None

        """
        self.extra['status'] = status

        if status == 'UP':
            self.log.info('status %s', status, extra=self.extra)
        elif status == 'DOWN':
            self.log.critical('status %s', status, extra=self.extra)
        elif status == 'unknown':
            self.log.warning('status %s', status, extra=self.extra)

    def _run_check(self):
        """Execute a check command.

        Returns:
            True if the exit code of the command was 0 otherwise False.

        """
        cmd = shlex.split(self.config['check_cmd'])
        self.log.info("running %s", ' '.join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        start_time = time.time()
        try:
            outs, errs = proc.communicate(timeout=self.config['check_timeout'])
        except subprocess.TimeoutExpired:
            self.log.error("check timed out")
            if proc.poll() is None:
                try:
                    proc.kill()
                except PermissionError:
                    self.log.warning("failed to kill check due to adequate "
                                     "access rights, check could be running "
                                     "under another user(root) via sudo")

            return False
        else:
            msg = "check duration {t:.3f}ms".format(
                t=(time.time() - start_time) * 1000)
            self.log.info(msg)
            if proc.returncode == 0:
                return True
            else:
                self.log.info("stderr from the check %s", errs)
                self.log.info("stdout from the check %s", outs)
                return False

    def _ip_assigned(self):
        """Check if IP prefix is assigned to loopback interface.

        Returns:
            True if IP prefix found assigned otherwise False.

        """
        output = []
        cmd = [
            '/sbin/ip',
            'address',
            'show',
            'dev',
            self.config['interface'],
            'to',
            self.ip_with_prefixlen,
        ]

        if self.ip_check_disabled:
            self.log.info("checking for IP assignment on interface %s is "
                          "disabled", self.config['interface'])
            return True

        self.log.debug("running %s", ' '.join(cmd))
        try:
            output = subprocess.check_output(
                cmd,
                universal_newlines=True,
                timeout=1)
        except subprocess.CalledProcessError as error:
            self.log.error("error checking IP-PREFIX %s: %s",
                           cmd, error.output)
            # Because it is unlikely to ever get an error we return True
            return True
        except subprocess.TimeoutExpired:
            self.log.error("timeout running %s", ' '.join(cmd))
            # Because it is unlikely to ever get a timeout we return True
            return True
        except ValueError as error:
            # We have been getting intermittent ValueErrors, see here
            # gist.github.com/unixsurfer/67db620d87f667423f6f6e3a04e0bff5
            # It has happened ~5 times and this code is executed from multiple
            # threads and every ~10secs on several (~40) production servers for
            # more than 18months.
            # It could be a bug in Python or system returns corrupted data.
            # As a consequence of the raised exception thread dies and the
            # service isn't monitored anymore!. So, we now catch the exception.
            # While checking if an IP is assigned, we get an error unrelated to
            # that prevents us from knowing if it's assigned. We simply don't
            # know. A retry logic could be a more proper solution.
            self.log.error("running %s raised ValueError exception:%s",
                           ' '.join(cmd), error)
            return True
        else:
            if self.ip_with_prefixlen in output:  # pylint: disable=E1135
                msg = "{i} assigned to loopback interface".format(
                    i=self.ip_with_prefixlen)
                self.log.debug(msg)
                return True
            else:
                msg = ("{i} isn't assigned to {d} interface"
                       .format(i=self.ip_with_prefixlen,
                               d=self.config['interface']))
                self.log.warning(msg)
                return False

        self.log.debug("I shouldn't land here!, it is a BUG")

        return False

    def _check_disabled(self):
        """Check if health check is disabled.

        It logs a message if health check is disabled and it also adds an item
        to the action queue based on 'on_disabled' setting.

        Returns:
            True if check is disabled otherwise False.

        """
        if (self.config['check_disabled'] and
                self.config['on_disabled'] == 'withdraw'):
            self.log.info("Check is disabled and ip_prefix will be withdrawn")
            del_operation = DeleteOperation(name=self.name,
                                            ip_prefix=self.ip_with_prefixlen,
                                            ip_version=self.ip_version)
            self.log.info("adding %s in the queue", self.ip_with_prefixlen)
            self.action.put(del_operation)
            self.log.info("Check is now permanently disabled")
            return True
        elif (self.config['check_disabled'] and
              self.config['on_disabled'] == 'advertise'):
            self.log.info("check is disabled, ip_prefix wont be withdrawn")
            add_operation = AddOperation(name=self.name,
                                         ip_prefix=self.ip_with_prefixlen,
                                         ip_version=self.ip_version)
            self.log.info("adding %s in the queue", self.ip_with_prefixlen)
            self.action.put(add_operation)
            self.log.info('check is now permanently disabled')
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
        # or unsuccessful health checks.
        check_state = 'Unknown'

        for key, value in self.config.items():
            self.log.debug("%s=%s:%s", key, value, type(value))

        # Service check will abort if it is disabled.
        if self._check_disabled():
            return

        interval = self.config['check_interval']
        start_offset = time.time() % interval
        # Go in a loop until we are told to stop
        while True:
            timestamp = time.time()
            if not self._ip_assigned():
                up_cnt = 0
                self.extra['status'] = 'down'
                self.log.warning("status DOWN because %s isn't assigned to "
                                 "loopback interface.",
                                 self.ip_with_prefixlen,
                                 extra=self.extra)
                if check_state != 'DOWN':
                    check_state = 'DOWN'
                    del_operation = DeleteOperation(
                        name=self.name,
                        ip_prefix=self.ip_with_prefixlen,
                        ip_version=self.ip_version)
                    self.log.info("adding %s in the queue",
                                  self.ip_with_prefixlen,
                                  extra=self.extra)
                    self.action.put(del_operation)
            elif self._run_check():
                if up_cnt == (self.config['check_rise'] - 1):
                    self.extra['status'] = 'up'
                    self.log.info("status UP", extra=self.extra)
                    # Service exceeded all consecutive checks. Set its state
                    # accordingly and put an item in queue. But do it only if
                    # previous state was different, to prevent unnecessary bird
                    # reloads when a service flaps between states.
                    if check_state != 'UP':
                        check_state = 'UP'
                        operation = AddOperation(
                            name=self.name,
                            ip_prefix=self.ip_with_prefixlen,
                            ip_version=self.ip_version)
                        self.log.info("adding %s in the queue",
                                      self.ip_with_prefixlen,
                                      extra=self.extra)
                        self.action.put(operation)
                elif up_cnt < self.config['check_rise']:
                    up_cnt += 1
                    self.log.info("going up %s", up_cnt, extra=self.extra)
                else:
                    self.log.error("up_cnt is higher %s, it's a BUG!",
                                   up_cnt,
                                   extra=self.extra)
                down_cnt = 0
            else:
                if down_cnt == (self.config['check_fail'] - 1):
                    self.extra['status'] = 'down'
                    self.log.info("status DOWN", extra=self.extra)
                    # Service exceeded all consecutive checks.
                    # Set its state accordingly and put an item in queue.
                    # But do it only if previous state was different, to
                    # prevent unnecessary bird reloads when a service flaps
                    # between states
                    if check_state != 'DOWN':
                        check_state = 'DOWN'
                        del_operation = DeleteOperation(
                            name=self.name,
                            ip_prefix=self.ip_with_prefixlen,
                            ip_version=self.ip_version)
                        self.log.info("adding %s in the queue",
                                      self.ip_with_prefixlen,
                                      extra=self.extra)
                        self.action.put(del_operation)
                elif down_cnt < self.config['check_fail']:
                    down_cnt += 1
                    self.log.info("going down %s", down_cnt, extra=self.extra)
                else:
                    self.log.error("up_cnt is higher %s, it's a BUG!",
                                   up_cnt,
                                   extra=self.extra)
                up_cnt = 0

            self.log.info("wall clock time %.3fms",
                          (time.time() - timestamp) * 1000,
                          extra=self.extra)

            # calculate sleep time
            sleep = start_offset - time.time() % interval
            if sleep < 0:
                sleep += interval
            self.log.debug("sleeping for %.3fsecs", sleep, extra=self.extra)
            time.sleep(sleep)
