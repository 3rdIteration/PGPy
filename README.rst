PGPy: Pretty Good Privacy for Python
====================================

.. image:: https://badge.fury.io/py/PGPy.svg
    :target: https://badge.fury.io/py/PGPy
    :alt: Latest stable version

.. image:: https://travis-ci.com/SecurityInnovation/PGPy.svg?branch=master
    :target: https://travis-ci.com/SecurityInnovation/PGPy?branch=master
    :alt: Travis-CI

.. image:: https://coveralls.io/repos/github/SecurityInnovation/PGPy/badge.svg?branch=master
    :target: https://coveralls.io/github/SecurityInnovation/PGPy?branch=master
    :alt: Coveralls

.. image:: https://readthedocs.org/projects/pgpy/badge/?version=latest
    :target: https://pgpy.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

`PGPy` is a Python library for implementing Pretty Good Privacy into Python programs, conforming to the OpenPGP specification per RFC 4880.

Features
--------

Currently, PGPy can load keys and signatures of all kinds in both ASCII armored and binary formats.

It can create and verify RSA, DSA, and ECDSA signatures, at the moment. It can also encrypt and decrypt messages using RSA and ECDH.

Installation
------------

To install PGPy, simply:

.. code-block:: bash

    $ pip install PGPy

Documentation
-------------

`PGPy Documentation <https://pgpy.readthedocs.io/en/latest/>`_ on Read the Docs

Discussion
----------

Please report any bugs found on the `issue tracker <https://github.com/SecurityInnovation/PGPy/issues>`_

You can also join ``#pgpy`` on Freenode to ask questions or get involved

Requirements
------------

- Python >= 3.6

  Tested with: 3.10, 3.9, 3.8, 3.7, 3.6

- `PyCryptodomex <https://pypi.python.org/pypi/pycryptodomex>`_

- `pyasn1 <https://pypi.python.org/pypi/pyasn1/>`_

Cipher Support Notes
~~~~~~~~~~~~~~~~~~~~

This fork uses `PyCryptodomex` as its cryptographic backend instead of `python-cryptography`.
As a result, the following symmetric ciphers are **not supported** for encryption:

- **Camellia** (128/192/256) - not available in PyCryptodomex
- **Twofish256** - not available in PyCryptodomex
- **IDEA** - insecure; only available for decryption of legacy messages

PGPy can still parse and recognize keys and messages that reference these algorithms, but cannot
perform encryption operations with them. All other algorithms (AES, TripleDES, CAST5, Blowfish)
are fully supported.

License
-------

BSD 3-Clause licensed. See the bundled `LICENSE <https://github.com/SecurityInnovation/PGPy/blob/master/LICENSE>`_ file for more details.
