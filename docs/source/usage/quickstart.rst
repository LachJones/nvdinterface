.. _quickstart:

Quickstart
----------


This guide gives a brief explanation of how to get started using this library.

Make sure that:

* nvdinterface is :ref:`installed <installation>`
* nvdinterface is :ref:`up-to-date <updating>`

Searching for a Vulnerability
-----------------------------

Searching for details of a known CVE ID is very simple.

Import the nvdinterface library:

.. code-block::

    >>> import nvdinterface

    Now, use the

Now, use the ``search_cves`` function to search for a known ID:

.. code-block::

    >>> result = nvdinterface.search_cves(cveId='CVE-2014-0160')

Examine the result:

.. code-block::

    >>> result
    {'resultsPerPage': 1, 'startIndex': 0, 'totalResults': 1, 'format': 'NVD_CVE', 'version': '2.0', 'timestamp': '2024-10-20T21:50:29.817', 'vulnerabilities': [<nvdinterface.vuln_types.CVE.CVE object>]}

Use resulting vulnerabilities:

.. code-block::

    >>> for vuln in result.vulnerabilities:
    >>>     print(vuln)
