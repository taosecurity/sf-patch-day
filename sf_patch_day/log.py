# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""The troubleshooting log: --verbose writes it to stderr, --log <file> to a file (both may be given).

Every part logs through log.info("section", "what was read or decided"). Nothing is logged unless asked for.
"""
import datetime
import sys

_sinks = []


def setup(verbose=False, log_file=None):
    """Open the sinks. Returns an error message (str) when the log file can't be opened, else None."""
    close()
    if verbose:
        _sinks.append(sys.stderr)
    if log_file:
        try:
            _sinks.append(open(log_file, "w", encoding="utf-8"))
        except OSError as e:
            return f"can't write the log file {log_file}: {e.strerror}. Fix: give --log a folder you can write to."
    return None


def info(section, msg):
    if not _sinks:
        return
    line = f"{datetime.datetime.now().strftime('%H:%M:%S')} [{section}] {msg}\n"
    for s in _sinks:
        s.write(line)
        s.flush()


def enabled():
    return bool(_sinks)


def close():
    for s in _sinks:
        if s is not sys.stderr:
            s.close()
    _sinks.clear()
