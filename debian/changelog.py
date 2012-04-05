#!/usr/bin/env python

from Registry import _version_
from datetime import datetime

with open("debian/changelog", "w") as fd:
    fd.write("""python-registry (%s) unstable; urgency=low

  * Upstream release

-- Willi Ballenthin <willi.ballenthin@gmail.com>  %s
""" % (_version_, datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')))

