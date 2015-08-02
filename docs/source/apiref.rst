Documentation for the Code
**************************


ifupdownmain
============

ifupdownmain is the main ifupdown module.

.. automodule:: ifupdownmain

.. autoclass:: ifupdownMain
   :members: up, down, reload, query

iface
=====

.. automodule:: iface

.. autoclass:: iface
   :members: state, status, flags, priv_flags, refcnt, lowerifaces, upperifaces, add_to_upperifaces, get_attr_value, get_attr_value_first, get_attr_value_n, update_config, update_config_with_status, get_config_attr_status, compare, dump_raw, dump, dump_pretty

.. autoclass:: ifaceState

.. autoclass:: ifaceStatus

.. autoclass:: ifaceJsonEncoder

scheduler
=========

.. automodule:: scheduler

.. autoclass:: ifaceScheduler
   :members: sched_ifaces

.. autoclass:: ifaceSchedulerFlags


networkinterfaces
=================

.. automodule:: networkinterfaces

.. autoclass:: networkInterfaces
   :members: load, subscribe

statemanager
============

.. automodule:: statemanager

.. autoclass:: pickling
   :members: save, save_obj, load

.. autoclass:: stateManager
   :members: read_saved_state, save_state

graph
=====

.. automodule:: graph

.. autoclass:: graph
   :members: topological_sort_graphs_all, generate_dots
