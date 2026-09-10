"""Private local JSON storage with atomic replacement.

POSIX modes protect qntm state from other local users; they are not encryption.
The selected storage directory must be dedicated to qntm, owned by this user,
and not a symlink. Existing directories and files are tightened when accessed.
"""

import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from contextlib import contextmanager

_locks = threading.local()


def _check_owner(info, path):
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"Private storage must be owned by the current user: {path}")


def private_directory(path):
    path = Path(path).absolute()
    # Never chmod a shared temporary root, filesystem root, or the user's home.
    if path.resolve() in {Path(path.anchor), Path.home().resolve(), Path(tempfile.gettempdir()).resolve()}:
        raise ValueError(f"Choose a dedicated qntm configuration directory: {path}")
    if not path.parent.exists():
        private_directory(path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise ValueError(f"Private storage directory must not be a symlink: {path}")
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        _check_owner(info, path)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"Private storage path is not a directory: {path}")
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return path


def _private_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if Path(path).is_symlink():
        raise ValueError(f"Private storage file must not be a symlink: {path}")
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        _check_owner(info, path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"Private storage requires a regular file without hard links: {path}")
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


def load_json(path, default=None):
    path = Path(path)
    # lexists catches dangling symlinks, which must not be treated as absent.
    if not os.path.lexists(path):
        return default
    private_directory(path.parent)
    with os.fdopen(_private_file(path), "r", encoding="utf-8") as stream:
        return json.load(stream)


def save_json(path, data):
    path = Path(path).absolute()
    parent = private_directory(path.parent)
    if os.path.lexists(path):
        os.close(_private_file(path))
    # Serialize before creating a temporary file or replacing existing contents.
    serialized = json.dumps(data, indent=2) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def private_lock(path, *, blocking=True, reentrant=False):
    """Process lock with explicit same-process/thread reentrancy when requested.

    Persistent lock files are never unlinked. A forked child must acquire its
    own lock, even when it inherits the parent's thread-local bookkeeping.
    """
    path = Path(path).absolute()
    held = getattr(_locks, 'held', None)
    if held is None:
        held = _locks.held = set()
    key = (os.getpid(), str(path))
    if reentrant and key in held:
        yield
        return
    private_directory(path.parent)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    fd = _private_file(path)
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        held.add(key)
        acquired = True
        yield
    finally:
        if acquired:
            held.discard(key)
        # Closing the descriptor releases the lock, including on exceptions.
        os.close(fd)
