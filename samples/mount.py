from __future__ import with_statement

import os
import sys
import stat
import errno
import inspect
import calendar

from fuse import FUSE, FuseOSError, Operations, fuse_get_context

from Registry import Registry


PERMISSION_ALL_READ = int("444", 8)


def unixtimestamp(ts):
    """
    unixtimestamp converts a datetime.datetime to a UNIX timestamp.
    @type ts: datetime.datetime
    @rtype: int
    """
    return calendar.timegm(ts.utctimetuple())


def log(func):
    """
    log is a decorator that logs the a function call with its
      parameters and return value.
    """
    def inner(*args, **kwargs):
        func_name = inspect.stack()[3][3]
        if func_name == "_wrapper":
            func_name = inspect.stack()[2][3]
        (uid, gid, pid) = fuse_get_context()
        pre = "(%s: UID=%d GID=%d PID=%d ARGS=(%s) KWARGS=(%s))" % (
            func_name, uid, gid, pid,
            ", ".join(map(str, list(args)[1:])), str(**kwargs))
        try:
            ret = func(*args, **kwargs)
            post = "  +--> %s" % (str(ret))
            sys.stderr.write("%s\n%s\n" % (pre, post))
            return ret
        except Exception as e:
            post = "  +--> %s" % (str(e))
            sys.stderr.write("%s\n%s" % (pre, post))
            raise e
    return inner


class FH(object):
    """
    FH is a class used to represent a file handle.
    """
    def __init__(self, fh, data):
        super(FH, self).__init__()
        self._fh = fh
        self._data = data

    def get_fh(self):
        return self._fh

    def get_data(self):
        return self._data

    def get_size(self):
        return len(self._data)


class EntryNotFoundError(Exception):
    pass


class RegFuseOperations(Operations):
    """
    RegFuseOperations is a FUSE driver for Registry hives.
    """
    def __init__(self, root, reg):
        self._root = root
        self._reg = reg
        self._opened_files = {}  # dict(int --> FH subclass)

    def _get_entry(self, path):
        if path == "/" or path == "":
            return self._reg.root()
        path = path.lstrip("/\\").replace("/", "\\")

        try:
            return self._reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            key, _, value = path.rpartition("\\")
            parent = self._reg.open(key)
            try:
                return parent.value(value)
            except Registry.RegistryValueNotFoundException:
                raise EntryNotFoundError()

    def _is_directory(self, entry):
        return isinstance(entry, Registry.RegistryKey)

    def _is_file(self, entry):
        return isinstance(entry, Registry.RegistryValue)

    # Filesystem methods
    # ==================
    #@log
    def getattr(self, path, fh=None):
        (uid, gid, pid) = fuse_get_context()

        working_path = path

        try:
            entry = self._get_entry(path)
        except EntryNotFoundError:
            return errno.ENOENT

        if self._is_directory(entry):
            mode = (stat.S_IFDIR | PERMISSION_ALL_READ)
            nlink = 2
            ts = unixtimestamp(entry.timestamp())
            size = 0
        else:
            mode = (stat.S_IFREG | PERMISSION_ALL_READ)
            nlink = 1
            ts = 0
            size = len(entry.raw_data())

        return {
            "st_atime": 0,
            "st_ctime": 0,
            #"st_crtime": unixtimestamp(record.standard_information().created_time()),
            "st_mtime": ts,
            "st_size": size,
            "st_uid": uid,
            "st_gid": gid,
            "st_mode": mode,
            "st_nlink": nlink,
        }

    #@log
    def readdir(self, path, fh):
        try:
            entry = self._get_entry(path)
        except EntryNotFoundError:
            return errno.ENOENT

        if not self._is_directory(entry):
            return

        # can't be a generator, since we *return* ENOENT above (not yield)
        ret = [".", ".."]

        for key in entry.subkeys():
            ret.append(key.name())

        for value in entry.values():
            ret.append(value.name())

        return ret

    @log
    def readlink(self, path):
        return path

    @log
    def statfs(self, path):
        return dict((key, 0) for key in ('f_bavail', 'f_bfree',
                                         'f_blocks', 'f_bsize', 'f_favail',
                                         'f_ffree', 'f_files', 'f_flag',
                                         'f_frsize', 'f_namemax'))

    @log
    def chmod(self, path, mode):
        return errno.EROFS

    @log
    def chown(self, path, uid, gid):
        return errno.EROFS

    @log
    def mknod(self, path, mode, dev):
        return errno.EROFS

    @log
    def rmdir(self, path):
        return errno.EROFS

    @log
    def mkdir(self, path, mode):
        return errno.EROFS

    @log
    def unlink(self, path):
        return errno.EROFS

    @log
    def symlink(self, target, name):
        return errno.EROFS

    @log
    def rename(self, old, new):
        return errno.EROFS

    @log
    def link(self, target, name):
        return errno.EROFS

    @log
    def utimens(self, path, times=None):
        return errno.EROFS

    # File methods
    # ============

    def _get_available_fh(self):
        """
        _get_available_fh returns an unused fh
        The caller must be careful to handle race conditions.
        @rtype: int
        """
        for i in xrange(65534):
            if i not in self._opened_files:
                return i

    @log
    def open(self, path, flags):
        if flags & os.O_WRONLY > 0:
            return errno.EROFS
        if flags & os.O_RDWR > 0:
            return errno.EROFS

        # TODO(wb): race here on fh used/unused
        fh = self._get_available_fh()

        try:
            entry = self._get_entry(path)
        except EntryNotFoundError:
            return errno.ENOENT

        data = entry.raw_data()
        self._opened_files[fh] = FH(fh, data)

        return fh

    #@log
    def read(self, path, length, offset, fh):
        return self._opened_files[fh].get_data()[offset:offset + length]

    @log
    def flush(self, path, fh):
        return ""

    @log
    def release(self, path, fh):
        del self._opened_files[fh]

    @log
    def create(self, path, mode, fi=None):
        return errno.EROFS

    @log
    def write(self, path, buf, offset, fh):
        return errno.EROFS

    @log
    def truncate(self, path, length, fh=None):
        return errno.EROFS

    @log
    def fsync(self, path, fdatasync, fh):
        return errno.EPERM


def main(hivepath, mountpoint):
    r = Registry.Registry(hivepath)
    handler = RegFuseOperations(mountpoint, r)
    FUSE(handler, mountpoint, foreground=True)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])




