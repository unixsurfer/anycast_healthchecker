# pylint: disable=superfluous-parens
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# pylint: disable=too-many-return-statements
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
    """Handles the health checking for a service.

    Arguments:
        service (str): The name of the service to monitor.
        config (dict): A dictionary with the configuration of the service.
        action (Queue obj): A queue object to place actions based on the result
        of the health check.
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
        self.ip_address = self.config['ip_prefix'].split('/')[0]
        self.prefix_length = self.config['ip_prefix'].split('/')[1]

        self.log = log
        self.log.info("loading check for {n}".format(n=self.name))
        self.extra = {
            'servicename': self.name,
            'ip_address': self.ip_address,
            'prefix_length': self.prefix_length,
        }
        self.ip_check_disabled = self.config['ip_check_disabled']

    def _run_check(self):
        """Executes a check command.

        Returns:
            True if the exit code of the command was 0 otherwise False.
        """
        cmd = shlex.split(self.config['check_cmd'])
        self.log.info("running {}".format(' '.join(cmd)), **self.extra)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        start_time = time.time()
        try:
            outs, errs = proc.communicate(timeout=self.config['check_timeout'])
        except subprocess.TimeoutExpired:
            self.log.error("check timed out", priority=80, **self.extra)
            if proc.poll() is None:
                try:
                    proc.kill()
                except PermissionError:
                    self.log.warning("failed to kill check due to adequate "
                                     "access rights, check could be running "
                                     "under another user(root) via sudo",
                                     priority=80, **self.extra)

            return False
        else:
            msg = "check duration {t:.3f}ms".format(
                t=(time.time() - start_time) * 1000)
            self.log.info(msg, **self.extra)
            if proc.returncode == 0:
                return True
            else:
                self.log.info("stderr from the check {}".format(errs))
                self.log.info("stdout from the check {}".format(outs))
                return False

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
            self.config['interface'],
            'to',
            self.config['ip_prefix'],
        ]

        if self.ip_check_disabled:
            msg = ("checking for IP assignment on interface {} is disabled".
                   format(self.config['interface']))
            self.log.info(msg, priority=50, **self.extra)
            return True

        self.log.debug("running {}".format(' '.join(cmd)), json_blob=False)
        try:
            out = subprocess.check_output(
                cmd,
                universal_newlines=True,
                timeout=1)
        except subprocess.CalledProcessError as error:
            msg = "error checking IP-PREFIX {c} {e}".format(c=cmd,
                                                            e=error.output)
            self.log.error(msg, priority=60, **self.extra)
            # Because it is unlikely to ever get an error we return True
            return True
        except subprocess.TimeoutExpired:
            msg = "timeout running {c}".format(c=' '.join(cmd))
            self.log.error(msg, priority=50, **self.extra)
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
            msg = ("running {c} raised ValueError exception:{e}"
                   .format(c=' '.join(cmd), e=error))
            self.log.error(msg, priority=50, **self.extra)
            return True
        else:
            if self.config['ip_prefix'] in out:  # pylint: disable=E1135
                msg = "{i} assigned to loopback interface".format(
                    i=self.config['ip_prefix'])
                self.log.debug(msg, json_blob=False)
                return True
            else:
                msg = "{i} NOT assigned to loopback interface".format(
                    i=self.config['ip_prefix'])
                self.log.warning(msg, priority=20, **self.extra)
                return False

        self.log.debug("I shouldn't land here!, it is a BUG",
                       priority=50, **self.extra)

        return False

    def _check_disabled(self):
        """Checks if health check is disabled.

        It logs a message if health check is disabled and it also adds an item
        to the action queue based on 'on_disabled' setting.

        Returns:
            True if check is disabled otherwise False.
        """
        if (self.config['check_disabled'] and
                self.config['on_disabled'] == 'withdraw'):
            self.log.info("Check is disabled and ip_prefix will be withdrawn",
                          priority=20, **self.extra)
            del_operation = DeleteOperation(name=self.name,
                                            ip_prefix=self.config['ip_prefix'],
                                            log=self.log, **self.extra)
            msg = "{i} added in queue".format(i=self.config['ip_prefix'])
            self.log.info(msg, **self.extra)
            self.action.put(del_operation)
            self.log.info("Check is now permanently disabled",
                          priority=20, status='disabled', **self.extra)
            return True
        elif (self.config['check_disabled'] and
              self.config['on_disabled'] == 'advertise'):
            self.log.info("check is disabled, ip_prefix wont be withdrawn",
                          priority=80, **self.extra)
            add_operation = AddOperation(name=self.name,
                                         ip_prefix=self.config['ip_prefix'],
                                         log=self.log, **self.extra)
            msg = "{i} add in queue".format(i=self.config['ip_prefix'])
            self.log.info(msg, **self.extra)
            self.action.put(add_operation)
            self.log.info('check is now permanently disabled',
                          priority=20, status='disabled', **self.extra)
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
            self.log.debug("{}={}:{}".format(key, value, type(value)),
                           json_blob=False)

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
                msg = ("status DOWN because {i} isn't assigned to loopback "
                       "interface."
                       .format(i=self.config['ip_prefix']))
                self.log.warning(msg, priority=80, status='down', **self.extra)
                if check_state != 'DOWN':
                    check_state = 'DOWN'
                    del_operation = DeleteOperation(
                        name=self.name,
                        ip_prefix=self.config['ip_prefix'],
                        log=self.log, **self.extra)
                    msg = "{i} in queue".format(i=self.config['ip_prefix'])
                    self.log.info(msg, **self.extra)
                    self.action.put(del_operation)
            elif self._run_check():
                if up_cnt == (self.config['check_rise'] - 1):
                    self.log.info("status UP", status='up', **self.extra)
                    # Service exceeded all consecutive checks. Set its state
                    # accordingly and put an item in queue. But do it only if
                    # previous state was different, to prevent unnecessary bird
                    # reloads when a service flaps between states.
                    if check_state != 'UP':
                        check_state = 'UP'
                        operation = AddOperation(
                            name=self.name,
                            ip_prefix=self.config['ip_prefix'],
                            log=self.log, **self.extra)
                        msg = "{i} in queue".format(i=self.config['ip_prefix'])
                        self.log.info(msg, **self.extra)
                        self.action.put(operation)
                elif up_cnt < self.config['check_rise']:
                    up_cnt += 1
                    msg = "going up {n}".format(n=up_cnt)
                    self.log.info(msg, **self.extra)
                else:
                    msg = "up_cnt higher, it's a BUG! {n}".format(n=up_cnt)
                    self.log.error(msg, priority=70, **self.extra)
                down_cnt = 0
            else:
                if down_cnt == (self.config['check_fail'] - 1):
                    self.log.info("status DOWN", priority=100, status='down',
                                  **self.extra)
                    # Service exceeded all consecutive checks.
                    # Set its state accordingly and put an item in queue.
                    # But do it only if previous state was different, to
                    # prevent unnecessary bird reloads when a service flaps
                    # between states
                    if check_state != 'DOWN':
                        check_state = 'DOWN'
                        del_operation = DeleteOperation(
                            name=self.name,
                            ip_prefix=self.config['ip_prefix'],
                            log=self.log, **self.extra)
                        msg = "{i} in queue".format(i=self.config['ip_prefix'])
                        self.log.info(msg, **self.extra)
                        self.action.put(del_operation)
                elif down_cnt < self.config['check_fail']:
                    down_cnt += 1
                    msg = "going down {n}".format(n=down_cnt)
                    self.log.info(msg, priority=40, **self.extra)
                else:
                    msg = "down_cnt higher, it's a BUG! {n}".format(n=down_cnt)
                    self.log.error(msg, priority=70, **self.extra)
                up_cnt = 0

            msg = ("wall clock time {t:.3f}ms"
                   .format(t=(time.time() - timestamp) * 1000))
            self.log.info(msg, json_blob=False)

            # calculate sleep time
            sleep = start_offset - time.time() % interval
            if sleep < 0:
                sleep += interval
            self.log.debug("sleep for {t:.3f}secs".format(t=sleep),
                           json_blob=False)
            time.sleep(sleep)
