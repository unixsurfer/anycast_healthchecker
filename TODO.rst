TODO
====

#. Improve the way we handle timeouts/errors when we run ip tool

#. Consider switching from threads to asyncio, requires to drop support for
   Pyhton versions < 3.5. I can live with that. We should do that only when
   the number of service checks is higher than ~50.
