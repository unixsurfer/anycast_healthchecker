# pylint: disable=superfluous-parens
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
# pylint: disable=attribute-defined-outside-init

"""
A library which provides helper functions and classes.
"""

import logging
import logging.handlers
import os
import sys
import socket
import json
import daemon
import requests

from anycast_healthchecker import __version__ as version


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
        # python-daemon>=2.1 has initgroups=True by default which requires
        # root privileges(CAP_SETGID capability).
        # Older versions don't have it, so we set it manually instead of
        # passing it to the supper()
        self.initgroups = False

    def open(self):
        """Redirects stdout/stderr to loggers and calls DaemonContext.open."""
        self._add_logger_files()
        daemon.DaemonContext.open(self)
        if self.stdout_logger:
            sys.stdout = self.stdout_logger
        if self.stderr_logger:
            sys.stderr = self.stderr_logger


def open_files_from_loggers(loggers):
    """Returns open files used by file-based logger handlers.

    Arguments:
        loggers (list): A list of logger objects.

    Returns:
        A list of open files used by file-based logger handlers.
    """
    open_files = []
    for logger in loggers:
        for handler in logger.logger.handlers:
            if hasattr(handler, 'stream') and \
               hasattr(handler.stream, 'fileno'):
                open_files.append(handler.stream)
    return open_files


class LoggerExt(object):
    """Create a logging.Logger class with extended functionality

    It wraps a Logger class into a file like object, which provides a handy
    way to redirect stdout/stdin to a logger. It also accepts a JSON blob as
    input and forwards it over HTTP to a central location. The JSON blob is
    built out of a certain data structure which isn't configurable. This
    provides a easy way to pass messages to an ElasticSearch infrastructure.

    Arguments
        name (str): The name for the logger.
        file_path (str): The absolute path of the log file.
        log_level (logging.level obj): The threshold for this logger.
        log_format (logging.Formatter): The format of this logger.
        maxbytes (int): Max size of the log before it is rotated.
        backupcount (int): Number of backup file to keep.


    Methods:
        write(string): Writes string to logger with newlines removed.
        flush(): Flushes logger messages.
        close(): Closes logger.

    Returns:
        A logger object.

    Note:
        See logging module for acceptable values for log_level
        and log_format.
    """
    def __init__(self,
                 name,
                 file_path,
                 log_level=logging.DEBUG,
                 log_format=None,
                 maxbytes=104857600,
                 backupcount=8,):

        if log_format is None:
            log_format = ('%(asctime)s [%(process)d] %(levelname)-8s '
                          '%(threadName)-32s %(message)s')
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        handler = logging.handlers.RotatingFileHandler(file_path,
                                                       maxBytes=maxbytes,
                                                       backupCount=backupcount)
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.jid = "anycast-healthchecker-{h}".format(
            h=socket.gethostname().split('.')[0])

    def __getattr__(self, name):
        """Return a logger function for emitting messages

        Because it acts as a proxy for all undefined attributes, we only
        allow the ones that we know Logger will accept.
        """
        _valid_methods = [
            'critical',
            'warning',
            'warn',
            'info',
            'notice',
            'debug',
            'error',
        ]
        if name in _valid_methods:
            def log(msg, priority=10, json_blob=True, **kwargs):
                """A wrapper around logger method

                It extends the capabilities by sending also the messages to
                a HTTP server.

                Arguments:
                    msg(string): A message to emit
                    priority(integer): The priority associated with the
                    messsage
                    json_blob(boolean): ``True`` to send a JSON blob
                    kwargs(dictinary): A dictionary with extra information to
                    add to the JSON blob

                Returns:
                    A logger function
                """
                _logger = getattr(self.logger, name)
                _logger(msg)

                # send msg over http only if we are configured
                if hasattr(self, 'server') and json_blob:
                    self._send_http(msg, priority, **kwargs)

            return log
        else:
            raise AttributeError

    def write(self, string):
        """Erases newline from a string and writes to the logger."""
        string = string.rstrip()
        if string:  # Don't log empty lines
            if hasattr(self, 'server'):
                self._send_http(string, priority=80)
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
        for handler in self.logger.handlers:
            handler.close()

    def add_central_logging(self,
                            server='127.0.0.1',
                            timeout=1,
                            protocol='http',
                            port=2813,
                            path='/'):
        """Extends logger to a HTTP client"""
        self.server = server
        self.timeout = timeout
        self.protocol = protocol
        self.port = port
        self.path = path
        # Use Session object from requests for enforcing HTTP persistence
        # connection (HTTP keep-alive) so the underlying TCP connection will be
        # reused and recycled. This reduces the stress on the HTTP entry point.
        self._http_sess = requests.Session()

    def _send_http(self, msg, priority=10, **kwargs):
        """Send msg as a JSON blob"""
        # These are the mandatory elements of the data structure which we send
        kwargs['softwareversion'] = version
        data = {
            'id': self.jid,
            'msg_type': 'anycast-healthchecker',
            'priority': priority,
            'msg_text': msg,
            'extra': kwargs,
        }
        # since we send JSON make sure we set Content-Type accordigly
        headers = {
            'Content-type': 'application/json',
            'Accept': 'text/plain',
        }
        url = "{proto}://{host}:{port}{path}".format(proto=self.protocol,
                                                     host=self.server,
                                                     port=self.port,
                                                     path=self.path)
        try:
            req = self._http_sess.post(url, timeout=self.timeout,
                                       data=json.dumps(data), headers=headers)
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.RequestException) as error:
            self.logger.warning("failed to send data to %s: %s",
                                self.server, error)
        else:
            if req.status_code == 200:
                try:
                    response = req.json()
                except ValueError as error:
                    self.logger.warning("failed to decode JSON response (%s)"
                                        ": %s", req.text, error)
                else:
                    # a valid response(JSON) looks like
                    # {"Status":"OK","Responses":["OK"]}
                    if (response['Status'] != 'OK' and
                            'OK' not in response['Responses']):
                        self.logger.warning("something went wrong when we sent"
                                            " (%s) as response from server "
                                            "was (%s)", data, req.text)
            else:
                self.logger.warning("failed to send JSON data, received HTTP "
                                    "status code %s with response content "
                                    "(%s)", req.status_code, req.text)
