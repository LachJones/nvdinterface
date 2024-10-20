.. _installation:

Installation
-----

Building from sources
-----

NVDClient is available `on Github <https://github.com/LachJones/nvdclient>`_.

You can clone the public repository:

.. code-block::

    $ git clone https://github.com/LachJones/nvdclient.git

Once you have the source, ensure you have the pre-requisite dependencies. This should occur in a python virtualenvironment (named ``.venv`` in this example) to prevent conflict with other packages on your system.

.. code-block::

    (.venv) $ python -m pip install --upgrade poetry

Then install the recently cloned sources:

.. code-block::

    (.venv) $ cd nvdclient
    (.venv) $ python -m poetry install
