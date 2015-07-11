# pylint: disable=superfluous-parens
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
#

"""
A library which provides helper functions and classes.
"""

import logging
import os
import sys
import daemon
import logging.handlers
import glob
import json
import ipaddress
import subprocess


def configuration_check(cfg_dir, log):
    options_type = {
        "name": str,
        "check_cmd": str,
        "check_interval": int,
        "check_timeout": int,
        "check_rise": int,
        "check_fail": int,
        "check_disabled": bool,
        "on_disabled": str,
        "ip_prefix": str
    }
    files = []
    for name in glob.glob(os.path.join(cfg_dir, '*.json')):
        files.append(name)
    if not files:
        sys.exit("No configuration was found in {}".format(cfg_dir))

    for filename in files:
        try:
            with open(filename, 'r') as conf:
                config = json.load(conf)
        except ValueError as error:
            sys.exit("{} isn't a valid JSON file: {}".format(filename,
                                                             str(error)))
        except (IOError, OSError) as error:
            sys.exit("Error for {}:{}".format(filename, str(error)))

        for option in options_type:
            if option not in config:
                sys.exit("{}: {} isn't configure in".format(filename, option))
            if not isinstance(config[option], options_type[option]):
                sys.exit("{}: {} has invalid type of value, it should be a "
                         "{}".format(filename,
                                     option,
                                     options_type[option].__name__))

        if (config['on_disabled'] != 'withdraw' and
                config['on_disabled'] != 'advertise'):
            sys.exit("{}: on_disable has invalid value({}), it should be either"
                     " withdraw or advertise".format(filename,
                                                     config['on_disabled']))

        # check if it is a valid IP
        try:
            ipaddress.IPv4Network(config['ip_prefix'])
        except (ipaddress.AddressValueError,
                ipaddress.NetmaskValueError,
                ValueError) as error:
            sys.exit("{}: {}".format(filename, str(error)))

        # ip_prefix must be passed with prefix length
        # We don't care about the value
        if '/' not in config['ip_prefix']:
            sys.exit("Prefix length is not specified in {}".format(
                config['ip_prefix']))

        cmd = config['check_cmd'].split()
        log.info("Checking if we can run the check_cmd")
        try:
            proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
            proc.kill()
        except (FileNotFoundError, PermissionError, OSError, IOError) as error:
            sys.exit("{}: failed to run {} wiht {}".format(filename,
                                                           config['check_cmd'],
                                                           str(error)))
        except:
            raise


    log.info("Configuration check passed")


class FileLikeLogger(object):
    """Wraps a logging.Logger class into a file like object.

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
                 umask=0o022,
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
            sys.stdout = FileLikeLogger(self.stdout_logger)
        if self.stderr_logger:
            sys.stderr = FileLikeLogger(self.stderr_logger)


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


def get_file_logger(
        name,
        file_path,
        log_level=logging.DEBUG,
        log_format=None,
        maxbytes=104857600,
        backupcount=8):
    """Sets up a rotating file logger.

    Arguments:
        name (str): The name for the logger.
        file_path (str): The absolute path of the log file.
        log_level (logging.level obj): The threshold for this logger.
        log_format (logging.Formatter): The format of this logger.
        maxbytes (int): Max size of the log before it is rotated.
        backupcount (int): Number of backup file to keep.

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
    handler = logging.handlers.RotatingFileHandler(
        file_path,
        maxBytes=maxbytes,
        backupCount=backupcount)
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    my_logger.addHandler(handler)

    return my_logger


def running(processid):
    """Checks the validity of a process ID.

    Arguments:
        processid (int): Process ID number.

    Returns:
        True if process ID is found otherwise False.
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
