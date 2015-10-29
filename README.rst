.. anycast_healthchecker
.. README.rst

=====================
anycast-healthchecker
=====================

    *A healthchecker for Anycasted services.*

.. contents::


Introduction
------------

**anycast-healthchecker** is a Python program to monitor a service and instruct
`Bird`_ daemon to advertise or withdraw a route associated with the service
based on the result of a health check. It uses the Python `daemon`_ library to
implement a well-behaved Unix daemon process and it also utilizes threading for
running each service check.

It makes sure that a route is only advertised from the local node if and only if
the service associated with that route is healthy. It works together with Bird
daemon to achieve this by utilizing a specific configuration logic.

What is Anycast
---------------

Anycast is a network address scheme where traffic from a sender has more than
one potential receivers, but only one of them receives it. Routing protocols,
`BGP`_ or `OSPF`_, decides which one of the potential receivers will actually
receive traffic based on the topology of the network. The main attribute which
contributes to the decision is the distance in terms of hops between the sender
and the receiver. The nearest receiver to a sender always receives the traffic
and this only changes if something changes on the network, another receiver
closest to the sender appears or current receiver disappears.

The three drawings below exhibit how traffic is routed between a sender and
multiple potential receivers when something changes on network.

.. image:: anycast-receivers-example1.png
   :scale: 60%
.. image:: anycast-receivers-example2.png
   :scale: 60%
.. image:: anycast-receivers-example3.png
   :scale: 60%

These potential receivers use `BGP`_ or `OSPF`_ by running an Internet Routing
daemon, Bird or quagga, to simultaneously announce the same destination IP
address from different places on the network. Due to the nature of Anycast
receivers can be located on any network across a global network infrastructure.

Anycast doesn't balance traffic as only one receiver attracts traffic from
senders. For instance, if there are two receivers which announce the same
destination IP address in certain location, traffic will be distributed across
those two receivers unevenly as senders can be spread across the network in an
uneven way and the main criteria for choosing were to route traffic is the
distance between the sender and receiver.

Anycast is being used as a mechanism to switch traffic between and within
data-centers for the following main reasons:

* the switch of traffic occurs without the need to enforce a change to the clients

In case of disaster of a service in one location, traffic from location will be
switched to another DC without any manual intervention and most importantly
without pushing a change to the clients which you don't always control.

* the switch happens within few milliseconds

The same technology can be used for balancing traffic using
`Equal-Cost Multi-Path`_.

ECMP routing is another network technology where traffic can be routed over
multiple paths. In the context of routing protocols, path is the route a packet
has to take in order to be delivered to a destination. Because these multiple
paths have the same cost (in terms of hops), traffic is balanced across them.
This provides the possibility to perform load-balancing of traffic across
multiple servers. Routers are the devices which perform load-balancing of
traffic and most of them use a deterministic way to select the server based on
the following four properties of IP packets:

* source IP
* source PORT
* destination IP
* destination PORT

Each unique combination of values for those four properties is called
`network flow`. For each different network flow a different destination server
is selected so traffic is evenly balanced across all servers.
These servers run an Internet Routing daemon in the same way as with Anycast
case but with the major difference that all servers receive traffic.
The main characteristic of this type of load-balancing is that is stateless.
Router balances traffic for a destination IP address based on the quadruple
flow without the need to understand and inspect protocols above Layer 3.
As a result it is very cheap in terms of resources and very fast at the same
time. This is commonly advertised as balancing of traffic at wire-speed.

How anycast-healthchecker works
-------------------------------

Current release of **anycast-healthchecker** supports only Bird daemon which
has to be configured in a specific way. Thus, it is mandatory to explain very
briefly how Bird handles advertisements for routes.

Bird maintains a routing information base (`RIB`_) and various protocols
import/export routes to/from it. The diagram below illustrates how Bird
advertises routes for IPs assigned to loopback interface to the rest of the
network using BGP protocol. Bird can also imports routes learned via BGP/OSPF
protocols, but this part of the routing process is irrelevant to the work of
anycast-healthchecker.


.. image:: bird_daemon_rib_explained.png
   :scale: 60%

A route is always associated with a service which runs locally on the box.
The Anycasted service is a daemon (HAProxy, Nginx, Bind etc) which processes
incoming traffic and listens to an IP (Anycast Service Address) for which a
route exists in RIB and it's advertised by Bird.

As it is exhibited in the above diagram a route is advertised only when:

#. IP is assigned to loopback interface
#. `direct`_ protocol from Bird imports a route in RIB for that IP
#. BGP/OSPF protocols exports that route from RIB to a network peer

The route associated with the Anycasted service must be either advertised or
withdrawn based on the health status of the service, otherwise traffic will
always be routed to the local node regardless of the status of the service.

Bird provides `filtering`_ capabilities with the help of a simple programming
language. A filter can be used to either accept or reject routes before they
are exported from RIB to the network.

We have a list of IP prefixes (<IP>/<prefix length>) stored in a text file.
Routes that **aren't** included in the list are filtered-out and they don't get
exported from RIB to the network. The white-list text file is sourced by Bird
upon startup, reload and reconfiguration. The following diagram illustrates how
this technique works:

.. image:: bird_daemon_filter_explained.png
   :scale: 60%

This configuration logic allows a separate process to update the list by adding
or removing IP prefixes and trigger a reconfigure on Bird in order to advertise
or withdraw routes.  **anycast-healthchecker** is the process which monitors
Anycasted services and based on the status of the health checks updates the list
of IP prefixes.

Bird doesn't allow the definition of a list with no elements and when that happens
Bird will emit an error and refuse to start. Because of this anycast-healthchecker
makes sure that there is always an IP prefix in the list, see dummy_ip_prefix
configuration option in `Daemon section`_.

Configuring anycast-healthchecker
---------------------------------

Because anycast-healthchecker is very much tied in with Bird daemon, we first
explain the configuration you need make in Bird. Then, we will cover the
configuration of anycast-healthchecker daemon, and then the configuration of
the health checks in particular and finally we'll cover the invocation of the
program from the command line.

Bird configuration
##################

Below is an example configuration for Bird which establishes the logic described
`How anycast-healthchecker works`_. It is the minimum configuration required by
anycast-healthchecker to function properly.

The most important part is the line `export where match_route();`. It forces all
routes to pass from `match_route` function before are exported::

    include "/etc/bird.d/*.conf";
    protocol device {
        scan time 10;
    }
    protocol direct direct1 {
        interface "lo";
            debug all;
            export none;
            import all;
    }
    template bgp bgp_peers {
        bfd on;
        debug all;
        import none;
        export where match_route();
        local as 64815;
    }
    protocol bgp BGP1 from bgp_peers {
        disabled no;
        description "Peer-BGP1";
        neighbor 10.248.7.254 as 64814;
    }

The match_function (/etc/bird.d/match-route.conf) look up the IP prefix of
the route to a list and accept the export if it finds the IP prefix in that
list::

    function match_route()
    {
        return net ~ ACAST_PS_ADVERTISE;
    }

The list ACAST_PS_ADVERTISE of IP prefixes is defined in /etc/bird.d/anycast-prefixes.conf::

    define ACAST_PS_ADVERTISE =
        [
            10.189.200.255/32,
            10.2.3.1
        ];

Configuring the daemon
######################

anycast-healthchecker uses the popular `INI`_ format for it's configuration files.
This is an example configuration file for the daemon (anycast-healthchecker.conf)::

    [DEFAULT]
    interface            = lo

    [daemon]
    pidfile              = /var/run/anycast-healthchecker/anycast-healthchecker.pid
    bird_conf            = /etc/bird.d/anycast-prefixes.conf
    bird_variable        = ACAST_PS_ADVERTISE
    bird_reconfigure_cmd = sudo /usr/sbin/birdc configure
    loglevel             = debug
    log_maxbytes         = 104857600
    log_backups          = 8
    log_file             = /var/log/anycast-healthchecker/anycast-healthchecker.log
    stderr_file          = /var/log/anycast-healthchecker/stderr.log
    stdout_file          = /var/log/anycast-healthchecker/stdout.log
    dummy_ip_prefix      = 10.189.200.255/32

The daemon doesn't need to run as root as long as it has sufficient privileges
to modify the Bird configuration (anycast-prefixes.conf) and trigger a
reconfiguration on bird by running `birdc configure`. In the above example we
use sudo and for that purpose (sudoers has been properly configured).

DEFAULT section
***************

Below are the default settings for all service checks, see `Configuring checks
for services`_ for explanation on the parameters.

:interface: lo
:check_interval: 10
:check_timeout: 2
:check_rise: 2
:check_fail: 2
:check_disabled: true
:on_disable: withdraw

Daemon section
**************

:pidfile: a file to store pid of the daemon
:bird_conf: a file with the variable containing IP prefixes allowed to be exported
:bird_variable: the name of the variable
:bird_reconfigure_cmd: a command to trigger a reconfiguration of Bird
:loglevel: log level
:log_maxbytes: maximum sizes in bytes for log files
:log_backups: number of old log files to maintain
:log_file: a file to log messages
:stderr_file: a file to redirect standard error messages emitted by the daemon
:stdout_file: a file to redirect standard output messages emitted by the daemon
:dummy_ip_prefix: a IP prefix in form of <IP>/<prefixlength> which will be always
                  present in the `bird_variable` to avoid having an empty list.


:NOTE: The dummy_ip_prefix **must** not be used by a service, assigned to
       loopback interface and configured anywhere on the network as
       anycast-healthchecker **does not** perform any checks for it.

:NOTE: Make sure there isn't any other process which modifies the file set in
       `bird_conf` as this file is managed by anycast-healthchecker.

Configuring checks for services
###############################

An example of a service check configuration::

    [foo.bar.com]
    check_cmd = /usr/bin/curl -A 'anycast-healthchecker' --fail --silent http://10.52.12.1/
    check_interval = 10
    check_timeout = 5
    check_fail = 2
    check_rise = 2
    check_disabled = false
    on_disabled = withdraw
    ip_prefix = 10.52.12.1/32

The configuration for a single service check is defined in one section.
The name of the section becomes the name of the service check and appears in
the log files for easier searching of errors/warnings messages.

:check_cmd: the command to run to determine the status of the service based
            on the return code. Complex health checking should be wrapped
            in a script file. Output is ignored.
:check_interval: how often to run the check in seconds
:check_timeout: set timeout in seconds for the check command
:check_fail: a service considered as down after <n> consecutive unsuccessful health checks
:check_rise: a service considered as up after <n> consecutive successful health checks
:check_disabled: either disable the check with `true` or enable it with `false`
:on_disabled: what to do when check is disabled, either withdraw or advertise
:ip_prefix: IP prefix associated with the service. It **must be** assigned to
            the interface set in `interface` parameter
:interface: the name of the interface that `ip_prefix` is assigned to

You can squeeze multiple sections in one file or one provide different files
per section.

Starting the daemon
###################

Daemon CLI usage::

    % anycast-healthchecker --help
    A simple healthchecker for Anycasted services.

    Usage:
        anycast-healthchecker [-f <file> -d <directory> -c ] [-p | -P]

    Options:
        -f, --file <file>  configuration file with settings for the daemon
                           [default: /etc/anycast-healthchecker.conf]
        -d, --dir <dir>    directory with configuration files for service checks
                           [default: /etc/anycast-healthchecker.d]
        -c, --check        perform a sanity check on configuration
        -p, --print        show default settings for daemon and service checks
        -P, --print-conf   show configuration
        -v, --version      show version
        -h, --help         show this screen

You can launch the daemon by supplying a configuration file and a directory with
configuration for service checks::

  % anycast-healthchecker -f ./anycast-healthchecker.conf -d ./anycast-healthchecker.d


At the root of the project there is System V init and a Systemd unit files for
a proper integration with OS startup tools.

Installation
------------

From Source::

   sudo python setup.py install

Build (source) RPMs::

   python setup.py clean --all; python setup.py bdist_rpm

Build a source archive for manual installation::

   python setup.py sdist


Release
-------

#. Bump version in anycast_healthchecker/__init__.py

#. Commit above change with::

      git commit -av -m'RELEASE 0.1.3 version'

#. Create a signed tag, pbr will use this for the version number::

      git tag -s 0.1.3 -m 'bump release'

#. Create the source distribution archive (the archive will be placed in the **dist** directory)::

      python setup.py sdist

#. pbr will update ChangeLog file and we want to squeeze them to the previous commit thus we run::

      git commit -av --amend

#. Move current tag to the last commit::

      git tag -fs 0.1.3 -m 'bump release'

#. Push changes::

      git push;git push --tags


Development
-----------
I would love to hear what other people think about **anycast_healthchecker** and provide
feedback. Please post your comments, bug reports, wishes on my `issues page
<https://github.com/unixsurfer/anycast_healthchecker/issues>`_.

Testing
#######

At the root of the project there is a `local_run.sh` script which is being used
for testing purposes and does the following:

#. Create the necessary directory structure under $PWD/var to store
   configuration and log files

#. Generates configuration for the daemon and for 2 service checks

#. Generates bird configuration(anycast-prefixes.conf)

#. Installes anycast-healthchecker using python3.4 setup.py install --user

#. Assigns 4 IPs (10.52.12.[1-4]) to loopback interface

#. Checks if bird daemon runs but it doesn't try to start if it's running

#. Starts the daemon as normal user and not as root

Requirements for running local_run.sh and having a workable setup

#. python3.4 installation available

#. Bird installed and configured as it is mentioned in `Bird configuration`_

#. sudo access to run sudo birdc configure

#. sudo access to assign IPs on the loopback interface

Licensing
---------

Apache 2.0

Acknowledgement
---------------
This program was originally developed for Booking.com.  With approval
from Booking.com, the code was generalised and published as Open Source
on github, for which the author would like to express his gratitude.

Contacts
--------

**Project website**: https://github.com/unixsurfer/anycast_healthchecker

**Author**: Pavlos Parissis <pavlos.parissis@gmail.com>

.. _Bird: http://bird.network.cz/
.. _BGP: https://en.wikipedia.org/wiki/Border_Gateway_Protocol
.. _OSPF: https://en.wikipedia.org/wiki/Open_Shortest_Path_First
.. _Equal-Cost Multi-Path: https://en.wikipedia.org/wiki/Equal-cost_multi-path_routing
.. _direct: http://bird.network.cz/?get_doc&f=bird-6.html#ss6.4
.. _filtering: http://bird.network.cz/?get_doc&f=bird-5.html
.. _RIB: https://en.wikipedia.org/wiki/Routing_table
.. _INI: https://en.wikipedia.org/wiki/INI_file
.. _daemon: https://pypi.python.org/pypi/python-daemon/
