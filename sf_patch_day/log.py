# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""The troubleshooting log: --verbose writes it to stderr, --log <file> to a file (both may be given).

Every part logs through log.info("section", "what was read or decided"). Nothing is logged unless asked for.
"""
import datetime
import sys
import unicodedata

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


def show(text):
    """Text with every control character shown as \\xNN (or \\uNNNN, \\UNNNNNNNN): the C0 and C1 controls (an ESC
    sequence could rewrite the terminal, a newline could fake a line), and the invisible format and line-separator
    characters (a right-to-left override could reorder the line), and a lone surrogate (a file name Windows or
    Linux gives back undecoded; a strict UTF-8 write would fail on it). Text from a DLL's version block, a zip member
    name or a file name can hold them. The dlls text report and every log line go through it."""
    out = []
    for c in str(text):
        n = ord(c)
        if unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            out.append(f"\\x{n:02x}" if n < 0x100 else f"\\u{n:04x}" if n < 0x10000 else f"\\U{n:08x}")
        else:
            out.append(c)
    return "".join(out)


def info(section, msg, lines=False):
    """One log line, escaped. lines=True is for our own multi-line text (a traceback, a list of problems): each of
    its lines becomes a log line of its own, with the same time and section, and is escaped the same way."""
    if not _sinks:
        return
    head = f"{datetime.datetime.now().strftime('%H:%M:%S')} [{section}] "
    parts = str(msg).rstrip("\n").split("\n") if lines else [msg]
    text = "".join(f"{head}{show(p)}\n" for p in parts)
    for s in _sinks:
        s.write(text)
        s.flush()


def enabled():
    return bool(_sinks)


def close():
    for s in _sinks:
        if s is not sys.stderr:
            s.close()
    _sinks.clear()
