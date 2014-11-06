#!/usr/local/bin/blue-python3.4
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# File name: anycast_healthchecker.py
#
# Creation date: 21-10-2014
#
# Created by: Pavlos Parissis <pavlos.parissis@booking.com>
#
import os
import sys
import daemon
import logging
import logging.handlers
import time
import signal
from threading import Thread, Event
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from lockfile.pidlockfile import PIDLockFile
import glob
import json
import subprocess
from queue import Queue, Empty

NAME_OF_CONSTANT = 'ACAST_PS_ADVERTISE'


def running(processid):
    """Checks the validity of a process ID.

    Arguments:
        processid (int): Process ID number.

    Returns:
        True if process id is found otherwise False.

    """
    try:
        # From kill(2)
        # If sig is 0 (the null signal), error checking is performed but no
        # signal is actually sent. The null signal can be used to check the
        # validity of pid
        os.kill(processid, 0)
    except OSError:
        return False

    return True


def get_file_logger(name, file_path, log_level=logging.DEBUG, log_format=None):
    """Sets up a rotating file logger.

    The rotation policy is fixed to 100MBs and 8 backup files are kept.

    Arguments:
        name (str): The name for the logger.
        file_path (str): The absolute path of the log file.
        log_level (logging.level obj): The threshold for this logger.
        log_format (logging.Formatter): The format of this logger.

    Returns:
        A logger object.

    Note:
        See logging module for acceptable values for log_level
        and log_format.
    """
    if log_format is None:
        log_format = ('%(asctime)s [%(process)d] %(levelname)-8s '
                      '%(threadName)-32s %(message)s')
    my_logger = logging.getLogger(name)
    my_logger.setLevel(log_level)
    handler = logging.handlers.RotatingFileHandler(file_path,
                                                   maxBytes=104857600,
                                                   backupCount=8)
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    my_logger.addHandler(handler)

    return my_logger


class FileLikeLogger(object):
    """Wraps a logging.Logger into a file like object.

    This is a handy way to redirect stdout/stdin to a logger.

    Arguments:
        logger (logger obj): A logger object.

    Methods:
        write(string): Writes string to logger with newlines removed.
        flush(): Flushes logger messages.
        close(): Closes logger.
    """

    def __init__(self, logger):
        self.logger = logger

    def write(self, string):
        """Erases newline from a string and writes to the logger."""
        string = string.rstrip()
        if string:  # Don't log emtpy lines
            for line in string.split('\n'):
                # Critical to log at any log level.
                self.logger.critical(line)

    def flush(self):
        """Flushes logger's data."""
        # In case multiple handlers are attached to the logger make sure
        # they are flushed.
        for handler in self.logger.handlers:
            handler.flush()

    def close(self):
        """Calls the closer method of the logger."""
        # In case multiple handlers are attached to the logger make sure
        # they are flushed.
        for handler in self.logger.handlers:
            handler.close()


def open_files_from_loggers(loggers):
    """Returns open files used by file-based logger handlers.

    Arguments:
        loggers (list): A list of logger objects.

    Returns:
        A list of open files used by file-based logger handlers.
    """
    open_files = []
    for logger in loggers:
        for handler in logger.handlers:
            if hasattr(handler, 'stream') and \
               hasattr(handler.stream, 'fileno'):
                open_files.append(handler.stream)
    return open_files


class LoggingDaemonContext(daemon.DaemonContext):
    """A subclass of daemom.DaemonContext to add support for loggers.

    Arguments:
        loggers_preserve (list): A list of loggers.
        stdout_logger (logger obj): A logger for stdout.
        stderr_logger (logger obj): A logger for stderr.

    Methods:
        open(): Overwrites open method of daemon.DaemonContext.
    """
    def _add_logger_files(self):
        """Adds all files related to loggers into files_preserve."""
        for logger in [self.stdout_logger, self.stderr_logger]:
            if logger:
                self.loggers_preserve.append(logger)
        logger_files = open_files_from_loggers(self.loggers_preserve)
        self.files_preserve.extend(logger_files)

    def __init__(self,
                 chroot_directory=None,
                 working_directory='/',
                 umask=0,
                 uid=None,
                 gid=None,
                 prevent_core=True,
                 detach_process=None,
                 files_preserve=None,   # changed default
                 loggers_preserve=None,  # new
                 pidfile=None,
                 stdout_logger=None,  # new
                 stderr_logger=None,  # new
                 # stdin,   omitted!
                 # stdout,  omitted!
                 # sterr,   omitted!
                 signal_map=None):

        self.stdout_logger = stdout_logger
        self.stderr_logger = stderr_logger
        self.loggers_preserve = loggers_preserve

        devnull_in = open(os.devnull, 'r+')
        devnull_out = open(os.devnull, 'w+')
        if files_preserve is not None:
            files_preserve.extend([devnull_in, devnull_out])
        else:
            files_preserve = [devnull_in, devnull_out]

        super(LoggingDaemonContext, self).__init__(
            chroot_directory=chroot_directory,
            working_directory=working_directory,
            umask=umask,
            uid=uid,
            gid=gid,
            prevent_core=prevent_core,
            detach_process=detach_process,
            files_preserve=files_preserve,
            pidfile=pidfile,
            stdin=devnull_in,
            stdout=devnull_out,
            stderr=devnull_out,
            signal_map=signal_map)

    def open(self):
        """Redirects stdout/stderr to loggers and calls DaemonContext.open."""
        self._add_logger_files()
        daemon.DaemonContext.open(self)
        if self.stdout_logger:
            file_like_obj = FileLikeLogger(self.stdout_logger)
            sys.stdout = file_like_obj
        if self.stderr_logger:
            file_like_obj = FileLikeLogger(self.stderr_logger)
            sys.stderr = file_like_obj


class ServiceCheck(Thread):
    """Handles a check for each service.

    It loads JSON configuration in memory and keeps running a check against
    the service until it receives a stop event.

    If configuration can not be opened or parsed it causes an exit on the main
    program.

    Arguments:
        config_file (str): The absolute path of the configuration file
        for the service check.
        stop_event(Event obj): A Event obj to singal the check to be stopped.
        action (Queue obj): A queue object to put health action
        log (logger obj): A logger object to use.

    Methods:
        run(): The run method of the thread.
    """

    def __init__(self, config_file, stop_event, action, log):
        super(ServiceCheck, self).__init__()
        self.daemon = True
        self.config_file = config_file
        self.stop_event = stop_event
        self.action = action
        self.log = log

        self.config = None
        self._load_config()
        if self.config is None:
            self.log.warning("No config!, exiting thread")
            return None

        self.name = self.config['name']

        self.log.info("Loading check for {}".format(self.name))

    def _load_config(self):
        """Loads a JSON configuration file into a data strucure."""
        try:
            with open(self.config_file, 'r') as conf:
                self.config = json.load(conf)
        except ValueError as error:
            self.log.error("Invalid JSON: {}".format(error))
        except (IOError, OSError) as error:
            self.log.error("Error for {}:{}".format(self.config_file, error))

    def _run_check(self):
        """Runs a check command.

        It utilizes timeout and catches stop events as well.

        Returns:
            True if the exit code of the command was 0 otherwise False.
        """
        cmd = self.config['check_cmd'].split()
        self.log.info("Running {}".format(' '.join(cmd)))
        proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)

        start_time = time.time()
        expire_time = start_time + self.config['check_timeout']
        # Wait to get a returncode, None => process is not finished
        while (time.time() < expire_time
               and proc.poll() is None
               and not self.stop_event.isSet()):
            time.sleep(0.1)

        if proc.poll() is None:
            proc.kill()
            self.log.error("Check timeout or received stop event")
            return False

        self.log.debug("Check duration {}secs".format(time.time() - start_time))

        return proc.returncode == 0

    def _ip_assigned(self):
        """Checks if IP-PREFIX is assigned to loopback interface.

        Returns:
            True if IP-PREFIX found assigned otherwise False.
        """
        cmd = ['/sbin/ip', 'address', 'show', 'dev', 'lo']

        self.log.debug("running {}".format(' '.join(cmd)))
        try:
            out = subprocess.check_output(cmd,
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
            self.log.error("Error checking IP-PREFIX {} {}".format(cmd,
                                                                   error.output))
            # Because it is unlikely to ever get an error I return True
            return True
        except subprocess.TimeoutExpired:
            self.log.error("Timeout running {}".format(' '.join(cmd)))
            # Because it is unlikely to ever get a timeout I return True
            return True

        self.log.debug("Code shouldn't land here!")

        return False

    def run(self):
        """Discovers the health of a service based on the result of the check.

        It runs until it receives a stop event and is responsible to
        put an item in the queue.
        If the check was successful after a number of consecutive successful
        health checks then it considers the service UP and require for its
        IP_PREFIX to be added in the BIRD configuration, otherwise ask for
        a removal.

        The rise and fail options prevents unnecessary configuration changes
        when the check is flapping.
        """
        up_cnt = 0
        down_cnt = 0
        # The current established state of the service check, it can be either
        # UP or DOWN but only after a number of consecutive successful or
        # failure health checks.
        previous_state = 'Unknown'

        for key, value in self.config.items():
            if key != 'name':
                self.log.debug("{}={}:{}".format(key, value, type(value)))

        # Service check will abort if it is disabled.
        if (self.config['check_disabled']
                and self.config['on_disabled'] == 'withdraw'):
            self.log.info("Check is disabled and ip_prefix will be withdrawn")
            self.action.put((self.name, self.config['ip_prefix'], 'del'))
            self.log.info("{} in queue".format(self.config['ip_prefix']))
            self.log.info("Check is now permanently disabled")
            return None
        elif (self.config['check_disabled']
              and self.config['on_disabled'] == 'advertise'):
            self.log.info("Check is disabled, ip_prefix wont be withdrawn")
            self.action.put((self.name, self.config['ip_prefix'], 'add'))
            self.log.info("{} in queue".format(self.config['ip_prefix']))
            self.log.info("Check is now permanently disabled")
            return None

        # Go in a loop until we are told to stop
        while not self.stop_event.isSet():

            if not self._ip_assigned():
                    up_cnt = 0
                    self.log.info(("Status DOWN because {} isn't assigned to"
                                   " to loopback interface, but IP-PREFIX isn't"
                                   " removed from BIRD configuration as direct1"
                                   " protocol in BIRD has already removed the"
                                   " route for that IP-PREFIX which triggered"
                                   " upstream routers to withdrawn the specific"
                                   " route").format(self.config['ip_prefix']))
                    if previous_state != 'DOWN':
                        previous_state = 'DOWN'
            elif self._run_check():
                if up_cnt == (self.config['check_rise'] - 1):
                    down_cnt = 0
                    self.log.info("Status UP")
                    # Service exceeded all consecutive checks, set its state
                    # accordingly and put an item in the queue to be picked up
                    # by the main thread.
                    if previous_state != 'UP':
                        previous_state = 'UP'
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
            elif not self._run_check():
                if down_cnt == (self.config['check_fail'] - 1):
                    up_cnt = 0
                    self.log.info("Status DOWN")
                    # Service exceeded all consecutive checks, set its state
                    # accordingly and put an item in the queue to be picked up
                    # by the main thread.
                    if previous_state != 'DOWN':
                        previous_state = 'DOWN'
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
            self.log.debug("Sleeping {}secs".format(
                self.config['check_interval']))
            # Sleep in iterations of 1 second rather the whole time.
            # This allows the thread to catch a stop event faster, so the main
            # program can be terminated faster.
            sleep_cnt = 0
            while sleep_cnt < self.config['check_interval']:
                if self.stop_event.isSet():
                    self.log.info("Received stop event")
                    return
                time.sleep(1)
                sleep_cnt += 1

        self.log.info("Received stop event")


class HealthChecker(object):
    """Lunches service checkers and triggers a reconfiguration on BIRD.

    This class should be instantiated once and daemonized.

    It looks in directory for configuration files in JSON format. Each file
    defines a service check with following attributes and is being lunched as
    an individual thread.
    {
        "name": "graphite-api.booking.com",
        "check_cmd": "absolute path of script which returns exit code 0 or 1",
        "check_interval": 10,
        "check_timeout": 5,
        "check_rise": 3,
        "check_fail": 2,
        "check_disabled": false,
        "on_disabled": "withdraw",
        "ip_prefix": "10.189.200.1/32"
    }

    It uses a Event object to send a stop event to all threads when SIGTERM and
    SIGHUP are sent. It uses a queue as a store for IP_PREFIXes to be removed
    from and added to BIRD configuration. The BIRD configuration file that is
    being modified, defines a constant of IP_PREFIXes for which routes are
    allowed to be announced via routing protocols. When an IP_PREFIX is
    removed BIRD daemon withdraws the route associated that IP_PREFIX.

    Arguments:
        log(logger): A logger to log messages.

        cfg_dir ('str'): The absolute path of a configuration directory
        which contains configuration files for each check.

        bird_conf_file('str'): The absolute path of file which contains
        the definition of constant used by BIRD daemon.

        bird_constant_name('str'): The constant name used in the bird
        configuration.

        stop_event(Queue obj): A queue to communicate stop events to threads.

        action(Queue obj): A queue of ip_prefixes and their action to
        take after health of a check is determined. An item is a tuple of 3
        elements
            1st: The name of the thread.
            2nd: ip_prefix.
            3nd: Action to take, either 'add' or 'del'.

    Methods:
        run(): Lunches checks and updates bird configuration based on
        the result of the check.
        catch_signal(signum, frame): Catches signals and sends stop events to
        all threads, and then exits main program

    """
    def __init__(self, log, cfg_dir, bird_conf_file, bird_constant_name):
        self.log = log
        self.cfg_dir = cfg_dir
        self.bird_conf_file = bird_conf_file
        self.bird_constant_name = bird_constant_name
        self.stop_event = Event()
        self.action = Queue()

        self.log.debug("Initialize HealthChecker")

    def _get_config_files(self):
        """Retrives the absolute file path of configuration files.

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

        Arguments:
            health_action (tuple): A 3 element tuple.

        Returns:
            True if BIRD configuration was updated otherwise False.

        """
        conf_updated = False
        prefixes = []
        name = health_action[0]
        ip_prefix = health_action[1]
        action = health_action[2]
        comment = ('# 10.189.200.255 is a Dummy and it SHOULD NOT BE REMOVED '
                   'AND USED.')

        try:
            bird_conf = open(self.bird_conf_file, 'r+')
            lines = bird_conf.read()
            for line in lines.splitlines():
                line = line.strip()
                if line.startswith('10.'):
                    prefixes.append(line.rstrip(','))
        except (IOError, OSError) as error:
            self.log.critical("Failed to open bird configuration")
            self.log.critical(error)
            self.log.critical("This is a FATAL error, exiting")
            sys.exit(1)

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

        # OK some IP_PREFIX is either removed or added, go and truncate the
        # configuration with the new data.
        bird_conf.seek(0)
        bird_conf.write("# Generated in {}\n".format(time.ctime()))
        bird_conf.write("{}\n".format(comment))
        bird_conf.write("define {} =\n".format(self.bird_constant_name))
        bird_conf.write("{}[\n".format(4 * ' '))
        if prefixes:
            for prefix in prefixes[:-1]:
                bird_conf.write("{}{},\n".format(8 * ' ', prefix))
            bird_conf.write("{}{}\n".format(8 * ' ',
                                            prefixes[len(prefixes) - 1]))
            bird_conf.write("{}];\n".format(4 * ' '))
        bird_conf.truncate()
        bird_conf.close()
        self.log.info("Bird configuration is updated")

        return conf_updated

    def _reload_bird(self):
        "Reloads BIRD daemon by issuing a reconfigure command on birdcl"
        _cmd = ['sudo', '/usr/sbin/birdcl', 'configure']
        try:
            _output = subprocess.check_output(_cmd,
                                              timeout=2,
                                              universal_newlines=True)
        except subprocess.TimeoutExpired:
            self.log.error("Reloading bird timeout")
            return
        except subprocess.CalledProcessError:
            self.log.error("Reloading bird returned non-zero exit")
            return

        if 'Reconfigured' in _output:
            self.log.info("Reloaded BIRD daemon")

    def run(self):
        """Lunches checks and triggers updates on BIRD configuration."""
        self.log.info("Lunching checks")
        _workers = []
        files = self._get_config_files()

        # Lunch a thread for each configuration
        self.log.info("Going to lunch {} threads".format(len(files)))
        for config_file in files:
            _thread = ServiceCheck(config_file,
                                   self.stop_event,
                                   self.action,
                                   self.log)
            _thread.start()
            _workers.append(_thread)

        # Stay running until we receive an stop event
        while not self.stop_event.is_set():
            try:
                health_action = self.action.get(1)
                self.log.info(("Returned an item from the queue for {} with "
                               "IP_PREFIX {} and action to {} from Bird "
                               "configuration").format(health_action[0],
                                                       health_action[1],
                                                       health_action[2]))

                is_updated = self._update_bird_prefix_conf(health_action)
                self.action.task_done()
                if is_updated:
                    self._reload_bird()
            except Empty:
                continue

        for _thread in _workers:
            _thread.join()

    def catch_signal(self, signum, frame):
        """A signal catcher.

        Upon catching a signal sends stop event to a queue, waits a bit
        and then exits the main progam.

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


def main():
    """This is a main function:-)

    Parses CLI arguments.
    Prevents running if another process is already running.
    Sets a PID lock file.
    Sets up loggers.
    Instantiate daemon.DaemonContext object.
    Instantiate a healtherchecker object which will be daemonized.
    Sets up signal catcher on daemonized object.
    Last but not least, daemonize this program.

    """
    # Set and parse arguments.
    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="""
        A Healthchecker for Anycasted services. Triggers updates to BIRD daemon
        based on the result of a check. It modifies a file which defines a
        constant array which is used by BIRD daemon in a filter function.
        It should be combined with BIRD daemon as by itself does nothing
        useful.
        """)
    parser.add_argument(
        '-c', '--config-dir',
        dest='cfg_dir',
        help='Configuration directory',
        default='/etc/anycast-servicecheck.d')
    parser.add_argument(
        '-p', '--pidfile',
        help='Pid file',
        default='/var/run/anycast-healthchecker/anycast-healthchecker.pid')
    parser.add_argument(
        '-l', '--log-level', dest='loglevel',
        help='Log level',
        choices=[
            'debug',
            'info',
            'warning',
            'error',
            'critical'
        ],
        default='debug')
    parser.add_argument(
        '--bird-conf', '-b', dest='bird_conf_file',
        default='/etc/bird.d/anycast-prefixes.conf',
        help='Bird config file')
    parser.add_argument(
        '--bird-constant-name', '-g', dest='bird_constant_name',
        default='ACAST_PS_ADVERTISE',
        help='Name of the constant used in Bird config file')
    parser.add_argument(
        '--log-file', '-f', dest='log_file',
        default='/var/log/anycast-healthchecker/anycast-healthchecker.log',
        help='Log file')
    parser.add_argument(
        '--stderr-file', '-e', dest='stderr_log_file',
        default='/var/log/anycast-healthchecker/stderr.log',
        help='Error log file')
    parser.add_argument(
        '--stdout-file', '-s', dest='stdout_log_file',
        default='/var/log/anycast-healthchecker/stdout.log',
        help='Standard output log file')
    args = parser.parse_args()

    # Catch already running process and clean up stale pid file.
    # It could be removed when this program is lunched by a
    # SysV-style initscript.
    if os.path.exists(args.pidfile):
        pid = int(open(args.pidfile).read().rstrip())
        if running(pid):
            print("Process {} is already running".format(pid))
            sys.exit(1)
        else:
            print("Cleaning stale pid file, past pid {}".format(pid))
            os.unlink(args.pidfile)

    # Get a PID lock file.
    pid_lockfile = PIDLockFile(args.pidfile)
    # Map input log level to numeric which can be accepted by loggers
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(args.loglevel))

    # Set up loggers for stdout, stderr and daemon stream
    log = get_file_logger('daemon', args.log_file, numeric_level)
    stdout_log = get_file_logger('stdout',
                                 args.stdout_log_file,
                                 log_level=numeric_level)

    stderrformat = ('%(asctime)s [%(process)d] line:%(lineno)d '
                    'func:%(funcName)s %(levelname)-8s %(threadName)-32s '
                    '%(message)s')
    stderr_log = get_file_logger('stderr',
                                 args.stderr_log_file,
                                 log_level=numeric_level,
                                 log_format=stderrformat)

    # Make some noise.
    log.debug('Before we are daemonized')
    stdout_log.debug('Before we are daemonized')
    stderr_log.debug('Before we are daemonized')

    # Get and set the DaemonContext.
    context = LoggingDaemonContext()
    context.loggers_preserve = [log]
    context.stdout_logger = stdout_log
    context.stderr_logger = stderr_log

    # Set pidfile for DaemonContext
    context.pidfile = pid_lockfile

    # Create our master process.
    healthchecker = HealthChecker(log,
                                  args.cfg_dir,
                                  args.bird_conf_file,
                                  args.bird_constant_name)

    # Set signal mapping to catch singals and act accordingly.
    context.signal_map = {
        signal.SIGHUP: healthchecker.catch_signal,
        signal.SIGTERM: healthchecker.catch_signal,
    }

    # OK boy go and daemonize yourself.
    with context:
        log.info('Running as a daemon')
        healthchecker.run()
# This is the standard boilerplate that calls the main() function.
if __name__ == '__main__':
    main()
