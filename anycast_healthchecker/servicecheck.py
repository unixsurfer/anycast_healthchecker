# pylint: disable=superfluous-parens
#

"""
A library which provides the ServiceCheck class.
"""

import json
import subprocess
import time
from threading import Thread


class ServiceCheck(Thread):
    """Handles a check for a service.

    It is a child class of Thread class.
    Loads JSON configuration in memory and keeps running a check against
    the service until it receives a stop event by the main program.

    If configuration can't be opened or can't be parsed, thread is stopped.
    TODO: I should use alert using passive check framework.

    Arguments:
        config_file (str): The absolute path of the configuration file
        for the service check.
        stop_event(Event obj): A Event obj to signal the termination of the
        check.
        action (Queue obj): A queue object to put health actions.
        log (logger obj): A logger object to use.

    Methods:
        run(): Run method of the thread.
    """

    def __init__(self, config_file, stop_event, action, log):
        """Initialize name and configuration of the thread."""
        super(ServiceCheck, self).__init__()
        self.daemon = True
        self.config_file = config_file
        self.stop_event = stop_event
        self.action = action
        self.log = log
        self.config = None

        # Load configuration and exit thread if configuration is not found.
        self._load_config()
        if self.config is None:
            self.log.error("Configuration was not parsed")
            self.name = 'unnamed_check'
            return None

        self.name = self.config['name']
        self.log.info("Loading check for {}".format(self.name))

    def _load_config(self):
        """Loads a JSON configuration file into a data structure."""
        try:
            with open(self.config_file, 'r') as conf:
                self.config = json.load(conf)
        except ValueError as error:
            self.log.error("{} isn't a valid JSON file: {}".format(
                self.config_file,
                error))
        except (IOError, OSError) as error:
            self.log.error("Error for {}:{}".format(self.config_file, error))

    def _run_check(self):
        """Executes a check command.

        It utilizes timeout and catches stop events as well.

        Returns:
            True if the exit code of the command was 0 otherwise False.
        """
        cmd = self.config['check_cmd'].split()
        self.log.info("Running {}".format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)

        start_time = time.time()
        expire_time = start_time + self.config['check_timeout']
        # Wait to get a return code, None => process is not finished
        while (time.time() < expire_time
               and proc.poll() is None
               and not self.stop_event.isSet()):
            time.sleep(0.1)

        self.log.debug("Check duration {}secs".format(
            time.time() - start_time))

        if proc.poll() is None:
            proc.kill()
            self.log.error("Check timed out or received stop event")
            return False

        return proc.returncode == 0

    def _ip_assigned(self):
        """Checks if IP-PREFIX is assigned to loopback interface.

        Returns:
            True if IP-PREFIX found assigned otherwise False.
        """
        cmd = ['/sbin/ip', 'address', 'show', 'dev', 'lo']

        self.log.debug("running {}".format(' '.join(cmd)))
        if self.stop_event.isSet():
            self.log.info("Received stop event")
            return

        try:
            out = subprocess.check_output(
                cmd,
                universal_newlines=True,
                timeout=1)
            if self.config['ip_prefix'] in out:
                self.log.debug("{} assigned to loopback interface".format(
                    self.config['ip_prefix']))
                return True
            else:
                self.log.debug("{} NOT assigned to loopback interface".format(
                    self.config['ip_prefix']))
                return False
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

        self.log.debug("I shouldn't land here!, it is a BUG")

        return False

    def _check_disabled(self):
        """Checks if service check is disabled.

        It logs a message if check is disabled and it also adds an item
        to the action queue based on 'on_disabled' setting.

        Returns:
            True if check is disabled otherwise False.
            NOTE: Returns False if check is disabled but 'on_disabled'
            setting has wrong value.
        """
        if (self.config['check_disabled']
                and self.config['on_disabled'] == 'withdraw'):
            self.log.info("Check is disabled and ip_prefix will be withdrawn")
            self.action.put((self.name, self.config['ip_prefix'], 'del'))
            self.log.info("{} in queue".format(self.config['ip_prefix']))
            self.log.info("Check is now permanently disabled")
            return True
        elif (self.config['check_disabled']
              and self.config['on_disabled'] == 'advertise'):
            self.log.info("Check is disabled, ip_prefix wont be withdrawn")
            self.action.put((self.name, self.config['ip_prefix'], 'add'))
            self.log.info("{} in queue".format(self.config['ip_prefix']))
            self.log.info("Check is now permanently disabled")
            return True
        elif self.config['check_disabled']:
            self.log.warning(("Configuration says check is disabled but the"
                              " 'on_disabled' setting has wrong value ({})."
                              " Valid valures are 'withdraw' and 'advertise'"
                              " Due to this misconfiguration check is not"
                              " disabled").format(self.config['on_disabled']))

        return False

    def run(self):
        """Discovers the health of a service.

        It runs until it receives a stop event and is responsible to put
        an item into the queue. If check is successful after a number of
        consecutive successful health checks then it considers service UP
        and requires for its IP_PREFIX to be added in BIRD configuration,
        otherwise ask for a removal.

        Rise and fail options prevent unnecessary configuration changes
        when the check is flapping.
        """
        up_cnt = 0
        down_cnt = 0
        # The current established state of the service check, it can be
        # either UP or DOWN but only after a number of consecutive
        # successful or failure health checks.
        check_state = 'Unknown'

        # Exit thread when config is empty
        if not self.config:
            self.log.error("Thread is stopped as configuration empty")
            return

        for key, value in self.config.items():
            self.log.debug("{}={}:{}".format(key, value, type(value)))

        # Service check will abort if it is disabled.
        if self._check_disabled():
            return

        # Go in a loop until we are told to stop
        while not self.stop_event.isSet():

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
                    # Service exceeded all consecutive checks.
                    # Set its state accordingly and put an item in queue.
                    # But to it only if previous state was different, to catch
                    # uncessary bird reloads when a service flaps between states
                    if check_state != 'UP':
                        check_state = 'UP'
                        self.action.put((self.name,
                                         self.config['ip_prefix'],
                                         'add'))
                        self.log.info(
                            "Queued {}".format(self.config['ip_prefix']))
                elif up_cnt < self.config['check_rise']:
                    up_cnt += 1
                    self.log.info("Going UP {}".format(up_cnt))
                else:
                    self.log.error("up_cnt higher! {}".format(up_cnt))
                down_cnt = 0
            else:
                if down_cnt == (self.config['check_fail'] - 1):
                    self.log.info("Status DOWN")
                    # Service exceeded all consecutive checks.
                    # Set its state accordingly and put an item in queue.
                    # But to it only if previous state was different, to catch
                    # uncessary bird reloads when a service flaps between states
                    if check_state != 'DOWN':
                        check_state = 'DOWN'
                        self.action.put((self.name,
                                         self.config['ip_prefix'],
                                         'del'))
                        self.log.info(
                            "Queued {}".format(self.config['ip_prefix']))
                elif down_cnt < self.config['check_fail']:
                    down_cnt += 1
                    self.log.info("Going down {}".format(down_cnt))
                else:
                    self.log.error("down_cnt higher! {}".format(down_cnt))
                up_cnt = 0
            self.log.debug("Sleeping {}secs".format(
                self.config['check_interval']))
            # Sleep in iterations of 1 second rather the whole time.
            # This allows the thread to catch a stop event faster and as
            # a result the main program can be terminated faster.
            sleep_cnt = 0
            while sleep_cnt < self.config['check_interval']:
                if self.stop_event.isSet():
                    self.log.info("Received stop event")
                    return
                time.sleep(1)
                sleep_cnt += 1

        self.log.info("Received stop event")
