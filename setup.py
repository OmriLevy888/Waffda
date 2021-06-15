#!/usr/bin/env python
from setuptools import setup, find_packages

VERSION = '0.0.1'
DESCRIPTION = 'IDA HexRays API wrapper'
LONG_DESCRIPTION =  'Wraps the Python API offered by IDA HexRays decompiler for' \
                    'more Pythonic scripting'

setup(
    name='waffda',
    version=VERSION,
    author='Omri Levy Shahar',
    author_email='omrilevy888@gmail.com',
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=[],
    keywords=['ida', 'hexrays', 'decompiler'],
    classifiers=['Development Status :: 0 - Alpha',
                 'Intended Audience :: HexRays decompiler users',
                 'Programming Language :: Python :: 3',
                 'Operating System :: Microsoft :: Windows',
                 'Operating System :: Linux'])
