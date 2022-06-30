#!/usr/bin/env python

from setuptools import setup
from Registry import _version_

setup(name='python-registry',
      version=_version_,
      description='Read access to Windows Registry files.',
      author='Willi Ballenthin',
      author_email='willi.ballenthin@gmail.com',
      url='https://github.com/williballenthin/python-registry',
      license='Apache License (2.0)',
      packages=['Registry'],
      classifiers = ["Programming Language :: Python",
                     "Programming Language :: Python :: 3",
                     "Operating System :: OS Independent",
                     "License :: OSI Approved :: Apache Software License"],
     install_requires=['enum-compat']
     )

