"""Consistent Unicode output for terminals, redirected output and Windows CI."""

import sys


def configure_console():
    # Do not reconfigure stdin: native console input/getpass retain their OS handling.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if callable(reconfigure):
            reconfigure(encoding='utf-8', errors='backslashreplace')
