.. anycast_healthchecker
.. README.rst

=====================
anycast-healthchecker
=====================

    *A healthchecker for Anycasted services.*

.. contents::


Introduction
------------

**anycast-healthchecker** monitors a service by doing periodic health checks and, based on the result, instructing `Bird`_ daemon to either advertise or withdraw the route to reach it. As a result Bird will only advertise routes for healthy services. Routes for both IPv4 and IPv6 addresses are supported.

Bird must be configured in a certain way to interface properly with anycast-healthchecker. The configuration is detailed later in this document.

anycast-healthchecker is a Python program, which runs in foreground and uses threading to run multiple service checks in parallel.
In older versions ( < 0.8.0 ), anycast-healthchecker used the `daemon`_ library to implement a well-behaved Unix daemon process. This changed when 0.8.0 was released and the daemonization of the process is now a task of systemd.

What is Anycast
---------------

Anycast is a network addressing scheme where traffic from a sender has more than one potential receivers, but only one of them receives it.
Routing protocols decide which one of the potential receivers will actually receive traffic, according to the topology of the network. The main attribute contributing to this decision is the cost of the network path between a sender and a receiver.

Cost is a protocol specific value (usually an integer) that has meaning only within the domain of the protocol itself, and it is used as a metric of distance.
Routing protocols provide default values for common topologies (`BGP`_ associates the cost of a path with the number of autonomous systems between the sender and the receiver, `OSPF`_ calculates the default cost based on the bandwidth of links), but its main use is to allow administrative control over traffic flow by specifying a cost according to business needs.

The closest receiver to a sender always receives the traffic; this changes only if something changes on the network, i.e. another receiver with a better path to the sender shows up or the current receiver disappears. If multiple receivers share the same distance from the sender, more than one might receive traffic, depending on how the routing protocol is configured.

The three pictures below show how traffic is routed between a sender and multiple potential receivers when something changes on network. In this example BGP routing protocol is used:

.. image:: anycast-receivers-example1.png
   :scale: 60%
.. image:: anycast-receivers-example2.png
   :scale: 60%
.. image:: anycast-receivers-example3.png
   :scale: 60%

These potential receivers use `BGP`_ or `OSPF`_ and simultaneously announce the same destination IP address from different places on the network. Due to the nature of Anycast, receivers can be located on any location across a global
network infrastructure.

Anycast doesn't balance traffic, as only one receiver attracts traffic from senders. For instance, if there are two receivers announcing the same destination IP address in different locations, traffic will be distributed between these two receivers unevenly, as senders can be spread across the network in an uneven way.

Anycast is being used as a mechanism to switch traffic between and within data-centers for the following main reasons:

* the switch of traffic occurs without the need to enforce a change on clients

In case of a service failure in one location, traffic to that location will be switched to another data-center without any manual intervention and, most importantly, without pushing a change to clients, which you don't have always
control on.

* the switch happens within few milliseconds

The same technology can be used for balancing traffic using `Equal-Cost Multi-Path`_.

ECMP routing is a network technology where traffic can be routed over multiple paths. In the context of routing protocols, path is the route a packet has to take in order to be delivered to a destination. Because these multiple paths share the same cost, traffic is balanced across them.

This grants the possibility to perform traffic load-balancing across multiple servers. Routers distribute traffic in a deterministic fashion, usually by selecting the next hop and looking at the following four properties of IP packets:

* source IP
* source PORT
* destination IP
* destination PORT

Each unique combination of these four properties is called network flow. For each different network flow a different destination is selected so that traffic is evenly balanced across all servers. These nodes run an Internet Routing software in the same way as in the Anycast case, but with the major difference that all servers receive traffic at the
same time.

The main characteristic of this type of load-balancing is that it is stateless. Router balances traffic to a destination IP address based on the quadruple network flow without the need to understand and inspect protocols above Layer3.
As a result, it is very cheap in terms of resources and very fast at the same time. This is commonly advertised as traffic balancing at "wire-speed".

**anycast-healthchecker** can be utilized in Anycast and ECMP environments.

How anycast-healthchecker works
-------------------------------

The current release of anycast-healthchecker supports only the Bird daemon, which has to be configured in a specific way. Therefore, it is useful to explain very briefly how Bird handles advertisements for routes.

Bird maintains a routing information base (`RIB`_) and various protocols import/export routes to/from it. The diagram below illustrates how Bird advertises IP routes, assigned on the loopback interface, to the rest of the network using BGP protocol. Bird can also import routes learned via BGP/OSPF protocols, but this part of the routing process is irrelevant to the functionality of anycast-healthchecker.


.. image:: bird_daemon_rib_explained.png
   :scale: 60%

A route is always associated with a service that runs locally on the box. The Anycasted service is a daemon (HAProxy, Nginx, Bind etc) that processes incoming traffic and listens to an IP (Anycast Service Address) for which a route exists in the RIB and is advertised by Bird.

As shown in the above picture, a route is advertised only when:

#. The IP is assigned to the loopback interface.
#. `direct`_ protocol from Bird imports a route for that IP in the RIB.
#. BGP/OSPF protocols export that route from the RIB to a network peer.

The route associated with the Anycasted service must be either advertised or withdrawn based on the health of the service, otherwise traffic will always be routed to the local node regardless of the status of the service.

Bird provides `filtering`_ capabilities with the help of a simple programming language. A filter can be used to either accept or reject routes before they are exported from the RIB to the network.

A list of IP prefixes (<IP>/<prefix length>) is stored in a text file. IP prefixes that **are not** included in the list are filtered-out and **are not** exported from the RIB to the network. The white-list text file is sourced by Bird upon startup, reload and reconfiguration. The following diagram illustrates how this technique works:

.. image:: bird_daemon_filter_explained.png
   :scale: 60%

This configuration logic allows a separate process to update the list by adding or removing IP prefixes and trigger a reconfiguration of Bird in order to advertise or withdraw routes.  **anycast-healthchecker** is that separate process. It monitors Anycasted services and, based on the status of the health checks, updates the list of IP prefixes.

Bird does not allow the definition of a list with no elements: if that happens Bird will produce an error and refuses to start. Because of this, anycast-healthchecker makes sure that there is always an IP prefix in the list, see ``dummy_ip_prefix`` and ``dummy_ip6_prefix`` settings in `Daemon section`_.

Configuring anycast-healthchecker
---------------------------------

Because anycast-healthchecker is very tied with with Bird daemon, the configuration of Bird has been explained first. Next, the configuration of anycast-healthchecker (including the configuration for the health checks) is covered and, finally, the options for invoking the program from the command line will be described.

IPv6 support
############

IPv4 and IPv6 addresses are supported by the Bird Internet Routing Daemon project by providing a different daemon per IP protocol version, bird for IPv4 and bird6 for IPv6. This implies that configuration files are split as well, meaning that you can't define IPv6 addresses in a configuration and source it by the IPv4 daemon.

Bird configuration
##################

The logic described in `How anycast-healthchecker works`_ can be accomplished by configuring:

#. an ``include`` statement to source other configuration files in
   ``bird.conf``
#. a function, ``match_route``, as an export filter for the routing
   protocol (BGP or OSPF)
#. a list of IP prefixes for routes which allowed to be exported by Bird

anycast-healthchecker **does not** install any of the aforementioned files.

bird.conf
*********

The most important parts are the lines ``include "/etc/bird.d/*.conf";`` and ``export where match_route();``. The former statement causes inclusion of other configuration files while the latter forces all routes to pass from the ``match_route`` function before they are exported. BGP protocol is used in the below example but OSPF protocol can be used as well::

    include "/etc/bird.d/*.conf";
    protocol device {
        scan time 10;
    }
    protocol direct direct1 {
        interface "lo";
            export none;
            import all;
    }
    template bgp bgp_peers {
        import none;
        export where match_route();
        local as 64815;
    }
    protocol bgp BGP1 from bgp_peers {
        disabled no;
        neighbor 10.248.7.254 as 64814;
    }

match-route.conf
****************

``match-route.conf`` file configures the ``match_route`` function, which performs the allow and deny of IP prefixes by looking at the IP prefix of the route in a list and exports it if it matches entry::

    function match_route()
    {
        return net ~ ACAST_PS_ADVERTISE;
    }

This is the equivalent function for IPv6::

    function match_route6()
    {
        return net ~ ACAST6_PS_ADVERTISE;
    }

anycast-prefixes.conf
*********************

``anycast-prefixes.conf`` file defines a list of IP prefixes which is stored in a variable named ``ACAST_PS_ADVERTISE``. The name of the variable can be anything meaningful but ``bird_variable`` setting **must** be changed accordingly.

::

    define ACAST_PS_ADVERTISE =
        [
            10.189.200.255/32
        ];

anycast-healthchecker removes IP prefixes from the list for which a service check is not configured. But, the IP prefix set in ``dummy_ip_prefix`` does not need a service check configuration.

This the equivalent list for IPv6 prefixes::

    define ACAST6_PS_ADVERTISE =
        [
            2001:db8::1/128
        ];

anycast-healthchecker creates ``anycast-prefixes.conf`` file for both IP versions upon startup if those file don't exist. After the launch **no other process(es) should** modify those files.

Use daemon settings ``bird_conf`` and ``bird6_conf`` to control the location of the files.

With the default settings those files are located under ``/var/lib/anycast-healthchecker`` and ``/var/lib/anycast-healthchecker/6``. Administrators must create those two directories with permissions ``755`` and user/group ownership to the account under which anycast-healthchecker runs.

Bird daemon loads configuration files by using the ``include`` statement in the main Bird configuration (`bird.conf`_). By default such ``include`` statement points to a directory under ``/etc/bird.d``, while ``anycast-prefixes.conf`` files are located under ``/var/lib/anycast-healthchecker`` directories. Therefore,
a link for each file must be created under ``/etc/bird.d`` directory. Administrators must also create those two links. Here is an example from a production server:

::

    % ls -ls /etc/bird.d/anycast-prefixes.conf
    4 lrwxrwxrwx 1 root root 105 Dec  2 16:08 /etc/bird.d/anycast-prefixes.conf ->
    /var/lib/anycast-healthchecker/anycast-prefixes.conf

    % ls -ls /etc/bird.d/6/anycast-prefixes.conf
    4 lrwxrwxrwx 1 root root 107 Jan 10 10:33 /etc/bird.d/6/anycast-prefixes.conf
    -> /var/lib/anycast-healthchecker/6/anycast-prefixes.conf

Configuring anycast-healthchecker
#################################

anycast-healthchecker uses the popular `INI`_ format for its configuration files. This is an example configuration file(/etc/anycast-healthchecker.conf) for configuring anycast-healthchecker::

    [DEFAULT]
    interface             = lo

    [daemon]
    pidfile               = /var/run/anycast-healthchecker/anycast-healthchecker.pid
    ipv4                  = true
    ipv6                  = false
    bird_conf             = /var/lib/anycast-healthchecker/anycast-prefixes.conf
    bird6_conf            = /var/lib/anycast-healthchecker/6/anycast-prefixes.conf
    bird_variable         = ACAST_PS_ADVERTISE
    bird6_variable        = ACAST6_PS_ADVERTISE
    bird_reconfigure_cmd  = sudo /usr/sbin/birdc configure
    bird6_reconfigure_cmd = sudo /usr/sbin/birdc6 configure
    dummy_ip_prefix       = 10.189.200.255/32
    dummy_ip6_prefix      = 2001:db8::1/128
    bird_keep_changes     = false
    bird6_keep_changes    = false
    bird_changes_counter  = 128
    bird6_changes_counter = 128
    purge_ip_prefixes     = false
    loglevel              = debug
    log_maxbytes          = 104857600
    log_backups           = 8
    log_server_port       = 514
    json_stdout           = false
    json_log_file         = false
    json_log_server       = false
    prometheus_exporter   = false
    prometheus_collector_textfile_dir = /var/cache/textfile_collector/
    prometheus_exporter_interval      = 20

The above settings are used as defaults when anycast-healthchecker is launched without a configuration file. anycast-healthchecker **does not** need to run as root as long as it has sufficient privileges to modify the Bird configuration set in ``bird_conf`` or ``bird6_conf``, and trigger a reconfiguration of Bird by running the command configured in ``bird_reconfigure_cmd`` or ``bird6_reconfigure_cmd``. In the above example ``sudo`` is used for that purpose (``sudoers`` file has been modified for that purpose).

DEFAULT section
***************

Below are the default settings for all service checks, see `Configuring checks for services`_ for an explanation of the parameters. Settings in this section can be overwritten in other sections.

:interface: lo
:check_interval: 10
:check_timeout: 2
:check_rise: 2
:check_fail: 2
:check_disabled: true
:on_disabled: withdraw
:ip_check_disabled: false
:custom_bird_reconfigure_cmd_timeout: 2

Daemon section
**************

Settings for anycast-healthchecker itself

* **pidfile** Defaults to **/var/run/anycast-healthchecker/anycast-healthchecker.pid**

File to store the process id. The parent directory must be created prior the initial launch.

* **ipv4** Defaults to **true**

``true`` enables IPv4 support and ``false`` disables it.
NOTE: anycast-healthchecker **will not** start if IPv4 support is disabled while there is an service check configured for IPv4 prefix.

* **ipv6** Defaults to **false**

``true`` enables IPv6 support and ``false`` disables it
NOTE: anycast-healthchecker **will not** start if IPv6 support is disabled while there is an service check configured for IPv6 prefix.

* **bird_conf** Defaults to **/var/lib/anycast-healthchecker/anycast-prefixes.conf**

File with the list of IPv4 prefixes allowed to be exported. If this file is a symbolic link then the destination and the link itself must be on the same mounted filesystem.

* **bird6_conf** Defaults to **/var/lib/anycast-healthchecker/6/anycast-prefixes.conf**

File with the list of IPv6 prefixes allowed to be exported. If this file is a symbolic link then the destination and the link itself must be on the same mounted filesystem.

* **bird_variable** Defaults to **ACAST_PS_ADVERTISE**

The name of the list defined in ``bird_conf``

* **bird6_variable** Defaults to **ACAST6_PS_ADVERTISE**

The name of the list defined in ``bird6_conf``

* **bird_reconfigure_cmd** Defaults to **sudo /usr/sbin/birdc configure**

Command to trigger a reconfiguration of IPv4 Bird daemon

* **bird6_reconfigure_cmd** Defaults to **sudo /usr/sbin/birdc6 configure**

Command to trigger a reconfiguration of IPv6 Bird daemon

* **dummy_ip_prefix** Defaults to **10.189.200.255/32**

An IP prefix in the form <IP>/<prefix length> which will be always available in the list defined by ``bird_variable`` to avoid having an empty list. The ``dummy_ip_prefix`` **must not** be used by any service or assigned to the interface set with ``interface`` or configured anywhere on the network as anycast-healthchecker **does not** perform any checks for it.

* **dummy_ip6_prefix** Defaults to **2001:db8::1/128**

An IPv6 prefix in the form <IPv6>/<prefix length> which will be always available in the list defined by ``bird6_variable`` to avoid having an empty list. The ``dummy_ip6_prefix`` **must not** be used by any service or assigned to the interface set with ``interface`` or configured anywhere on the network as anycast-healthchecker **does not** perform any checks for it.

* **bird_keep_changes** Defaults to **false**

Keep a history of changes for ``bird_conf`` file by copying it to a directory. During the startup of anycast-healthchecker a directory with the name ``history`` is created under the directory where ``bird_conf`` file resides. The daemon has to have sufficient privileges to create that directory.

* **bird6_keep_changes** Defaults to **false**

Keep a history of changes for ``bird6_conf`` file by copying it to a directory. During the startup of anycast-healthchecker a directory with the name ``history`` is created under the directory where ``bird6_conf`` file resides. The daemon has to have sufficient privileges to create that directory.
WARNING: When keeping a history of changes is enabled for both IP versions then configuration files set in ``bird_conf`` and ``bird6_conf`` settings **must** be stored on two different directories.

* **bird_changes_counter** Defaults to **128**

How many ``bird_conf`` files to keep in the ``history`` directory.

* **bird6_changes_counter** Defaults to **128**

How many ``bird6_conf`` files to keep in the ``history`` directory.

* **purge_ip_prefixes** Defaults to **false**

During start-up purge IP-Prefixes from configuration files set in ``bird_conf`` and ``bird6_conf``, which don't have a service check associated with them.

NOTE: Those IP-Prefixes are always removed from the configuration files set in ``bird_conf`` and in ``bird6_conf`` settings when anycast-healthchecker updates those files. ``purge_ip_prefixes`` is considered only during start-up and was introduced in order to be compatible with the behavior of previous releases, which didn't remove those IP-Prefixes on start-up.

* **loglevel** Defaults to **debug**

Log level to use, possible values are: debug, info, warning, error, critical

* **log_file** Defaults to **STDOUT**

File to log messages to. The parent directory must be created prior the initial
launch.

* **log_maxbytes** Defaults to **104857600** (bytes)

Maximum size in bytes for log files. It is only used if **log_file** is set to
a file.

* **log_backups** Defaults to **8**

Number of old log files to maintain. It is only used if **log_file** is set to
a file.

* **stderr_file** Defaults to **STDERR**

File to redirect standard error to. The parent directory must be created prior the initial launch.

* **log_server** Unset by default

Either the IP address or the hostname of an UDP syslog server to forward logging messages.

* **log_server_port** Defaults to **514**

The port on the remote syslog server to forward logging messages over UDP.

* **json_stdout** Defaults to **false**

``true`` enables structured logging for STDOUT.

* **json_log_file** Defaults to **false**

``true`` enables structured logging when **log_file** is set to a file.

* **json_log_server** Defaults to **false**

``true`` enables structured logging when **log_server** is set to a remote UDP
syslog server.

* **prometheus_exporter** Defaults to **false**

``true`` enables prometheus exporter.

* **prometheus_collector_textfile_dir** Defaults to **/var/cache/textfile_collector/**

The directory to store the exported statistics.

* **prometheus_exporter_interval** Defaults to **20** seconds

How often to export Prometheus metrics.

* **splay_startup** Unset by default

The maximum time to delay the startup of service checks. You can use either integer or floating-point number as a value.

In order to avoid launching all checks at the same time, after anycast-healthchecker is started, we can delay the 1st check in random way. This can be useful in cases where we have a lot of service checks and launching all them at the same time can overload the system.  We randomize the delay of the 1st check for each service and **splay_startup** sets the maximum time we can delay that 1st check.

The interval of the check doesn't drift, thanks to 9cbbeaff455c49b35670c, and as a result the service checks will be always launched in different times during the life time of anycast-healthchecker.

Prometheus exporter
************************

anycast-healthchecker comes with a Prometheus exporter to expose various statistics. This functionality is not enabled by default and users need to set **prometheus_exporter** setting to **true** and also adjust **prometheus_collector_textfile_dir** parameter according to their setup.

Below is the exported metrics when there are three service checks configured::

    # HELP anycast_healthchecker_service_state The status of the service check: 0 = down, 1 = up
    # TYPE anycast_healthchecker_service_state gauge
    anycast_healthchecker_service_state{ip_prefix="fd12:aba6:57db:ffff::1/128",service_name="foo1IPv6.bar.com"} 0.0
    anycast_healthchecker_service_state{ip_prefix="10.52.12.1/32",service_name="foo.bar.com"} 0.0
    anycast_healthchecker_service_state{ip_prefix="10.52.12.2/32",service_name="foo1.bar.com"} 0.0
    # HELP anycast_healthchecker_service_check_duration_milliseconds Service check duration in milliseconds
    # TYPE anycast_healthchecker_service_check_duration_milliseconds gauge
    anycast_healthchecker_service_check_duration_milliseconds{ip_prefix="10.52.12.1/32",service_name="foo.bar.com"} 5.141496658325195
    # HELP anycast_healthchecker_service_check_ip_assignment Service IP assignment check: 0 = not assigned, 1 = assigned
    # TYPE anycast_healthchecker_service_check_ip_assignment gauge
    anycast_healthchecker_service_check_ip_assignment{ip_prefix="10.52.12.1/32",service_name="foo.bar.com"} 1.0
    anycast_healthchecker_service_check_ip_assignment{ip_prefix="fd12:aba6:57db:ffff::1/128",service_name="foo1IPv6.bar.com"} 0.0
    anycast_healthchecker_service_check_ip_assignment{ip_prefix="10.52.12.2/32",service_name="foo1.bar.com"} 1.0
    # HELP anycast_healthchecker_service_check_timeout_total The number of times a service check timed out
    # TYPE anycast_healthchecker_service_check_timeout_total counter
    anycast_healthchecker_service_check_timeout_total{ip_prefix="10.52.12.2/32",service_name="foo1.bar.com"} 3.0
    # HELP anycast_healthchecker_service_check_timeout_created The number of times a service check timed out
    # TYPE anycast_healthchecker_service_check_timeout_created gauge
    anycast_healthchecker_service_check_timeout_created{ip_prefix="10.52.12.2/32",service_name="foo1.bar.com"} 1.698693786243282e+09
    # HELP anycast_healthchecker_service_check_exitcode The exit code of the check command
    # TYPE anycast_healthchecker_service_check_exitcode gauge
    anycast_healthchecker_service_check_exitcode{ip_prefix="10.52.12.2/32",service_name="foo1.bar.com"} 126.0
    anycast_healthchecker_service_check_exitcode{ip_prefix="10.52.12.1/32",service_name="foo.bar.com"} 0.0
    # HELP anycast_healthchecker_uptime Uptime of the process in seconds since the epoch
    # TYPE anycast_healthchecker_uptime gauge
    anycast_healthchecker_uptime 1.6986938162371802e+09
    # HELP anycast_healthchecker_state The current state of the process: 0 = down, 1 = up
    # TYPE anycast_healthchecker_state gauge
    anycast_healthchecker_state 1.0
    # HELP anycast_healthchecker_version_info Version of the software
    # TYPE anycast_healthchecker_version_info gauge
    anycast_healthchecker_version_info{version="0.9.1"} 1.0
    # HELP anycast_healthchecker_service The configured service checks
    # TYPE anycast_healthchecker_service gauge
    anycast_healthchecker_service{ip_prefix="10.52.12.1/32",service_name="foo.bar.com"} 1.0
    anycast_healthchecker_service{ip_prefix="fd12:aba6:57db:ffff::1/128",service_name="foo1IPv6.bar.com"} 1.0
    anycast_healthchecker_service{ip_prefix="10.52.12.2/32",service_name="foo1.bar.com"} 1.0


How to configure logging
************************

By default anycast-healtchecker logs messages to STDOUT, while messages related to unhandled exceptions or crashes go to STDERR. But it is possible to log such messages to a file and/or to a remote UDP syslog server.

anycast-healthchecker doesn't log to STDOUT/STDERR when either log file or a remote UDP syslog server is configured.

You can configure it to use a log file and a remote UDP syslog server at the same time, so logging messages can be stored locally and remotely. This is convenient when remote log server is in trouble and loses log messages.

The best logging configuration in terms of resiliency is to enable logging only to a remote UDP syslog server. Sending data over UDP protocol is done in no-blocking mode and therefore anycast-healthchecker isn't blocked in any way
when it logs messages. Furthermore, when it logs to a log file and there isn't any more space available on the filesystem, the software will crash. You can easily avoid this failure by using UDP syslog server.

Last but not least, anycast-healthchecker handles the rotation of old log files, so you don't need to configure any other tools(logrotate) for that.

JSON logging
************

You can configure anycast-healthchecker to send structured logging messages. This is quite important in environments with a lot of servers and Anycasted services.

You can enable structured logging for STDOUT, log file and remote UDP syslog server. Currently, it isn't possible to add/remove keys from the structured logging data. The followings are the keys that are present in the structure:


* asctime: Human-readable time when the log message was created, example value 2017-07-23 09:43:28,995.

* levelname: Text logging level for the message, example value WARNING.

* process: Process ID, example value 23579

* message: The logged message.

* prefix_length: The prefix length of the Anycast Address associated with the logged message, example value 128.
  This key isn't present for messages, which were logged by the parent thread.

* status: The status of the service when message was logged, possible values are down, up and unknown.
  This key isn't present for messages, which were logged by the parent thread.

* ip_address: The Anycast IP address of the monitored service for which the message was logged, example value fd12:aba6:57db:ffff::2
  This key isn't present for messages, which were logged by the parent thread.

* ip_check_disabled: Either ``true`` when the assignment check of ``ip_prefix`` to the interface is disabled, otherwise ``false``.
  This key isn't present for messages, which were logged by the parent thread.

* version: The running version of anycast-healthchecker, example value 0.7.4.

* program: The process name, defaults to anycast-healthchecker.

* service_name: The name of the service defined in configuration for which the   message was logged, example value foo1IPv6.bar.com. Logging messages from the parent thread will have value "MainThread".

Configuring checks for services
###############################

The configuration for a single service check is defined in one section.
Here are few examples::

    [foo.bar.com]
    check_cmd         = /usr/bin/curl --fail --silent http://10.52.12.1/
    check_interval    = 10
    check_timeout     = 2
    check_fail        = 2
    check_rise        = 2
    check_disabled    = false
    on_disabled       = withdraw
    ip_prefix         = 10.52.12.1/32

    [foo6.bar.com]
    check_cmd         = /usr/bin/curl --fail 'http://[fd12:aba6:57db:ffff::1]:8888'
    check_timeout     = 5
    check_rise        = 2
    check_fail        = 2
    check_disabled    = false
    on_disabled       = withdraw
    ip_prefix         = fd12:aba6:57db:ffff::1/128
    ip_check_disabled = false

The name of the section becomes the name of the service check and appears in the log files for easier searching of error/warning messages.

* **check_cmd** Unset by default

The command to run to determine the status of the service based **on the return code**. Complex health checking should be wrapped in a script. When check command fails, the stdout and stderr appears in the log file.

* **check_interval** Defaults to **2** (seconds)

How often to run the check

* **check_timeout** Defaults to **2** (seconds)

Maximum time in seconds for the check command to complete. anycast-healthchecker will try kill the check if it doesn't return after *check_timeout* seconds. If *check_cmd* runs under another user account (root) via sudo then it won't be killed.  anycast-healthchecker could run as root to overcome this problem, but it is highly recommended to run it as normal user.

* **check_fail** Defaults to **2**

A service is considered DOWN after these many consecutive unsuccessful health checks

* **check_rise** Defaults to **2**

A service is considered HEALTHY after these many consecutive successful health checks

* **check_disabled** Defaults to **false**

``true`` disables the check, ``false`` enables it

* **on_disabled** Defaults to **withdraw**

What to do when check is disabled, either ``withdraw`` or ``advertise``

* **ip_prefix** Unset by default

IP prefix associated with the service. It **must be** assigned to the interface set in ``interface`` parameter unless ``ip_check_disabled`` is set to ``true``. Prefix length is optional and defaults to 32 for IPv4 addresses and to 128 for IPv6 addresses.

* **ip_check_disabled** Defaults to **false**

``true`` disables the assignment check of ``ip_prefix`` to the interface set in ``interface``, ``false`` enables it.

If the ``check_cmd`` checks the availability of the service by sending a request to the Anycasted IP address then this request may be served by another node that advertises the same IP address on the network. This usually happens
when the Anycasted IP address is not assigned to loopback or any other interface on the local node.

Therefore, it should be only enabled in environments where the network or the network configuration of the local node prevents the request from ``check_cmd`` to be forwarded to another node.

* **interface** Defaults to **lo**

The name of the interface that ``ip_prefix`` is assigned to

* **custom_bird_reconfigure_cmd** Unset by default

A custom command to trigger a reconfiguration of Bird daemon. This overwrites the value of **bird_reconfigure_cmd** and **bird6_reconfigure_cmd** settings. This setting allows the use of a custom command to trigger a reconfiguration of Bird daemon after an IP prefix is either added to or removed from Bird configuration. If return code is not a zero value then an error is logged together with STDERR of the command, if there is any. anycast-healthchecker passes one argument to the command, which is *up* when IP prefix is added or *down* when is removed, so the command can perform different things depending the status of the service.

* **custom_bird_reconfigure_cmd_timeout** Defaults to **2** (seconds)

Maximum time in seconds for the **custom_bird_reconfigure_cmd** to complete. anycast-healthchecker will try kill the command if it doesn't return after **custom_bird_reconfigure_cmd_timeout** seconds. If **custom_bird_reconfigure_cmd** runs under another user account (root) via sudo then it won't be killed.  anycast-healthchecker could run as root to overcome this problem, but it is highly recommended to run it as normal user.


Multiple sections may be combined in one file or provide one file per section. File must be stored under one directory and their name should use ``.conf`` as suffix (foo.bar.com.conf).

Starting anycast-healthchecker
##############################

CLI usage::

    anycast-healthchecker --help
    A simple healthchecker for Anycasted services.

    Usage:
        anycast-healthchecker [ -f <file> -c -p -P ] [ -d <directory> | -F <file> ]

    Options:
        -f, --file=<file>          read settings from <file>
                                   [default: /etc/anycast-healthchecker.conf]
        -d, --dir=<dir>            read settings for service checks from files
                                   under <dir> directory
                                   [default: /etc/anycast-healthchecker.d]
        -F, --service-file=<file>  read <file> for settings of a single service
                                   check
        -c, --check                perform a sanity check on configuration
        -p, --print                show default settings for anycast-healthchecker
                                   and service checks
        -P, --print-conf           show running configuration with default settings
                                   applied
        -v, --version              show version
        -h, --help                 show this screen

You can launch it by supplying a configuration file and a directory with configuration files for service checks::

  anycast-healthchecker -f ./anycast-healthchecker.conf -d ./anycast-healthchecker.d

At the root of the project there is System V init and a Systemd unit file for proper integration with OS startup tools.

Systemd and SysVinit integration
################################

Under contrib/systemd and contrib/SysVinit directories there are the necessary startup files that can be used to start anycast-healthchecker on boot.

**IMPORTANT:** Version 0.8.0 dropped support for daemonization and therefore you can't use the System V init script stored under contrib/SysVinit directory with newer versions. If you want to use version 0.8.0 and higher on Operating Systems that don't support Systemd then you have to use a tool like supervisord.

Nagios check
############

Under contrib/nagios directory there is a nagios plugin to check if the program is up and if all threads are running.

Installation
------------

Use pip::

    pip install anycast-healthchecker

From Source::

   sudo python -m pip install .

Build a python wheel for manual installation::

   python -m pip install build; python -m build --wheel


Release
-------

#. Bump version in anycast_healthchecker/__init__.py

#. Commit above change with::

      git commit -av -m'RELEASE 0.1.3 version'

#. Create a signed tag, pbr will use this for the version number::

      git tag -s 0.1.3 -m 'bump release'

#. Create the package wheel (the whl file will be placed in the **dist** directory)::

      python -m pip install build; python -m build --wheel

#. pbr will update ChangeLog file and we want to squeeze them to the previous commit thus we run::

      git commit -av --amend

#. Move current tag to the last commit::

      git tag -fs 0.1.3 -m 'bump release'

#. Push changes::

      git push; git push --tags


Development
-----------
I would love to hear what other people think about **anycast_healthchecker** and provide feedback. Please post your comments, bug reports and wishes on my `issues page <https://github.com/unixsurfer/anycast_healthchecker/issues>`_.

Testing
#######

At the root of the project there is a ``local_run.sh`` script which you can use
for testing purposes. It does the following:

#. Creates the necessary directory structure under $PWD/var to store
   configuration and log files

#. Generates configuration for the daemon and for 2 service checks

#. Generates bird configuration(anycast-prefixes.conf)

#. Installs anycast-healthchecker with ``python3 -m pip install .``

#. Assigns 4 IPv4 addresses and 2 IPv6 addresses to loopback interface

#. Checks if bird daemon runs but it does not try to start if it is down

#. Starts the daemon as normal user and not as root

Requirements for running ``local_run.sh``

#. python3 installation

#. A working python virtual environment, use the excellent tool virtualenvwrapper

#. Bird installed and configured as it is mentioned in `Bird configuration`_

#. sudo access to run ``birdc configure`` and ``birdc6 configure``

#. sudo access to assign IPs on the loopback interface using ``ip`` tool

Contributors
############

The following people have contributed to project with feedback, commits and code reviews

- Károly Nagy (@charlesnagy)
- Nick Demou (@ndemou)
- Ralf Ertzinger (@alufu)
- Carlo Rengo (@sevencastles)

Licensing
---------

Apache 2.0

Acknowledgement
---------------
This program was originally developed for Booking.com.  With approval from Booking.com, the code was generalised and published as Open Source on github, for which the author would like to express his gratitude.

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
.. _requests: https://github.com/kennethreitz/requests
