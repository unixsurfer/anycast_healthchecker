TODO
====

#. Sanity check on configuration

   - check boolean values
   - check valid IPs
   - check check_command

#. On startup check there are prefixes in bird's conf without a corresponding
   configuration file

#. Add proper example configuration in README

#. Add description in README about how we instruct Bird daemon to add/remove
   routes

#. Add support for configuration file

#. Add support for graphite metrics

#. Include install/test script

#. Review comments in code

#. Consider using configparser module and migrate from json to INI files

#. Make configurable the interface we check if IP_PREFIXs are assigned. I can't
   believe someone wont use loopback interface for anycasted IPs but you never
   know.
