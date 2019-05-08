import os.path

import pytest

from Registry import Registry


@pytest.fixture
def hive():
    path = os.path.join(os.path.dirname(__file__), "reg_samples", "issue22.hive")
    return Registry.Registry(path)
