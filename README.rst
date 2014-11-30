.. anycast_healthchecker
.. README.rst

anycast_healthchecker
=================

    *A healtchecker for Anycated services.*

.. contents::

Release
-------

To make a release you should first create a signed tag, pbr will use this for the version number::

   git tag -s 0.0.9 -m 'bump release'
   git push --tags

Create the source distribution archive (the archive will be placed in the **dist** directory)::

   python setup.py sdist

Installation
------------

From Source::

   sudo python setup.py install

Build (source) RPMs::

   python setup.py clean --all; python setup.py bdist_rpm

Booking.com instructions::

   python setup.py clean --all
   python setup.py sdist
   scp dist/anycast_healthchecker-0.0.9.tar.gz bkbuild-201.lhr4.prod.booking.com:~/git_tree/packages/blue-python/anycast-healthchecker
   ssh bkbuild-201.lhr4.prod.booking.com
   cd ~/git_tree/packages/blue-python/anycast-healthchecker
   vi anycast-healthchecker.spec
   cd ..
   ./bin/build_package --norepo anycast-healthchecker

Build a source archive for manual installation::

   python setup.py sdist

Usage
-----
TOBEADDED

Licensing
---------

Propietary License (c) 2014 Booking.com

Contacts
--------

**Project website**: https://git.booking.com/git/?p=anycast_healthchecker.git;a=summary

**Author**: Palvos Parissis <pavlos.parissis@booking.com>
