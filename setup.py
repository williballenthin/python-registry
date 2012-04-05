#!/usr/bin/env python

from distutils.core import setup
from Registry import _version_

setup(name='python-registry',
      version=_version_,
      description='Read access to Windows Registry files.',
      author='Willi Ballenthin',
      author_email='willi.ballenthin@gmail.com',
      url='http://www.williballenthin.com/registry/',
      license='Apache License (2.0)',
      packages=['Registry'],
     )

