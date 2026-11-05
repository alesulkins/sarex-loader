"""Nonblocking advisory locks; closing the fd releases the process lock."""

import os


def lock_file(fd, *, shared=False):
    if os.name == 'nt':
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBRLCK if shared else msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
