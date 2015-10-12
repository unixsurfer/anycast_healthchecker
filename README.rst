.. anycast_healthchecker
.. README.rst

=====================
anycast_healthchecker
====================

    *A healthchecker for Anycasted services.*

.. contents::


Introduction
------------

**anycast_healthchecker** is a Python program to monitor a service and instruct
`Bird`_ daemon to advertise or withdraw a route associated with the service
based on the results of the health check.

It makes sure that a route is only advertised from the local node if and only if
the service is healthy. It works together with `Bird`_ daemon to achieve this
using a specific configuration. Thus, **anycast_healthchecker**  is useful when is
used in conjuction with `Bird`_ daemon and with a specific configuration logic
in place.

`Bird`_ is a powerful and functional dynamic IP routing daemon with a lot of
capabilities and features. Current release of **anycast_healthchecker**
supports only `Bird`_ daemon and its configuration.


How it works
------------


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

**Author**: Palvos Parissis <pavlos.parissis@gmail.com>

.. _Bird: http://bird.network.cz/

