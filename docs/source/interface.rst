.. _interface:

NVD Interface
-------------------

.. automodule:: nvdinterface

This part of the documentation covers all the functionality of NV.

Main Interface
--------------

The primary functionality of this module can be accessed by these methods.

.. autofunction:: search_cves
.. autofunction:: search_cves_all
.. autofunction:: cve_history
.. autofunction:: cve_history_all

The above functions may return objects of the following types:

.. toctree::
    :maxdepth: 2

    types/cve
    types/cvss
