import Registry

from fixtures import *


def test_file_type(hive):
    assert hive._regf.file_type() == Registry.RegistryParse.FileType.FILE_TYPE_PRIMARY
