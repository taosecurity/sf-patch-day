# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""The Creations change report: compare the game's ContentCatalog.txt with a saved earlier copy.

ContentCatalog.txt is a JSON object: a "ContentCatalog" header ({"Description", "Version"}) and one entry per
Creation, keyed by its ID (TM_<uuid>), with AchievementSafe, Files, FilesSize, Timestamp, Title and Version.
The game rewrites Timestamp when a save loads, so Timestamp is never compared. The game's file is only read.
"""
import datetime
import json
import os
import re
import tempfile

from . import log

MAX_BYTES = 64 * 1024 * 1024
HEADER = "ContentCatalog"
IGNORED = ("Timestamp",)
KNOWN = ("Version", "Title", "Files", "FilesSize", "AchievementSafe")
_UNIX_VERSION = re.compile(r"^\d{10}\.(.+)$")


class CreationsError(Exception):
    pass


def show_version(v):
    """1757190740.1.0.0 -> 1.0.0 (the leading Unix time dropped); anything else as it is."""
    v = "" if v is None else str(v)
    m = _UNIX_VERSION.match(v)
    return m.group(1) if m else v


def _files(entry):
    v = entry.get("Files")
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def summary(cid, entry):
    """The JSON form of one Creation."""
    return {"id": cid, "title": str(entry.get("Title") or ""), "version": str(entry.get("Version") or ""),
            "files": _files(entry), "files_size": entry.get("FilesSize"),
            "achievement_safe": entry.get("AchievementSafe")}


def _no_constant(name):
    raise ValueError(f"{name} isn't a number a catalog holds")


def _int(text):
    if len(text) > 4300:  # the limit newer Pythons set; older ones (3.9) have none
        raise ValueError("a number too long to read")
    return int(text)


def read(path, what, fix):
    """(raw bytes, header dict, {id: entry}) of a catalog file. Raises CreationsError naming the file and a fix."""
    try:
        size = os.path.getsize(path)
        if size > MAX_BYTES:
            raise CreationsError(f"the {what} {path} is {size // (1024 * 1024)} MB, over the 64 MB a Creations "
                                 f"catalog could be. Fix: {fix}")
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as e:
        raise CreationsError(f"can't read the {what} {path}: {e.strerror}. Fix: {fix}")
    if len(raw) > MAX_BYTES:
        raise CreationsError(f"the {what} {path} is over 64 MB. Fix: {fix}")
    try:
        data = json.loads(raw.decode("utf-8-sig"), parse_constant=_no_constant, parse_int=_int)
    except UnicodeDecodeError:
        raise CreationsError(f"the {what} {path} isn't UTF-8 text. Fix: {fix}")
    except json.JSONDecodeError as e:
        raise CreationsError(f"the {what} {path} isn't valid JSON (line {e.lineno}: {e.msg}). Fix: {fix}")
    except RecursionError:
        raise CreationsError(f"the {what} {path} isn't a Creations catalog (nested too deeply). Fix: {fix}")
    except ValueError as e:  # NaN or Infinity, or a number too long to read
        raise CreationsError(f"the {what} {path} isn't a Creations catalog ({str(e).split(';')[0]}). Fix: {fix}")
    if not isinstance(data, dict):
        raise CreationsError(f"the {what} {path} isn't a Creations catalog (not a JSON object). Fix: {fix}")
    header = data.get(HEADER)
    if not isinstance(header, dict):
        raise CreationsError(f"the {what} {path} isn't a Creations catalog (no \"{HEADER}\" header). Fix: {fix}")
    entries = {}
    for k, v in data.items():
        if k == HEADER:
            continue
        if not isinstance(v, dict):
            raise CreationsError(f"the {what} {path} has an entry that isn't an object ({k}). Fix: {fix}")
        entries[k] = v
    log.info("creations", f"read {what} {path}: {len(raw)} bytes, {len(entries)} Creation(s), catalog version "
                          f"{header.get('Version')!r}")
    return raw, header, entries


def changes(old, new):
    """What changed in one Creation, Timestamp left out: {key: {...}} (empty when nothing did)."""
    out = {}
    if str(old.get("Version") or "") != str(new.get("Version") or ""):
        out["version"] = {"old": str(old.get("Version") or ""), "new": str(new.get("Version") or "")}
    if str(old.get("Title") or "") != str(new.get("Title") or ""):
        out["title"] = {"old": str(old.get("Title") or ""), "new": str(new.get("Title") or "")}
    of, nf = _files(old), _files(new)
    ok, nk = {x.casefold() for x in of}, {x.casefold() for x in nf}
    added = sorted({x for x in nf if x.casefold() not in ok}, key=str.casefold)
    removed = sorted({x for x in of if x.casefold() not in nk}, key=str.casefold)
    if added or removed:
        out["files"] = {"added": added, "removed": removed}
    if old.get("FilesSize") != new.get("FilesSize"):
        out["files_size"] = {"old": old.get("FilesSize"), "new": new.get("FilesSize")}
    if old.get("AchievementSafe") != new.get("AchievementSafe"):
        out["achievement_safe"] = {"old": old.get("AchievementSafe"), "new": new.get("AchievementSafe")}
    for key in sorted((set(old) | set(new)) - set(KNOWN) - set(IGNORED)):
        if old.get(key) != new.get(key):
            out[key] = {"old": old.get(key), "new": new.get(key)}
    return out


def _order(item):
    return (item["title"].casefold(), item["id"])


def compare(old_entries, new_entries):
    """The report body: added, removed, updated (with changes), unchanged and Timestamp-only counts."""
    added = sorted((summary(k, v) for k, v in new_entries.items() if k not in old_entries), key=_order)
    removed = sorted((summary(k, v) for k, v in old_entries.items() if k not in new_entries), key=_order)
    updated, unchanged, ts_only = [], 0, []
    for k in new_entries.keys() & old_entries.keys():
        o, n = old_entries[k], new_entries[k]
        c = changes(o, n)
        if c:
            updated.append({"id": k, "title": str(n.get("Title") or ""), "changes": c})
        elif any(o.get(f) != n.get(f) for f in IGNORED):
            ts_only.append(k)
        else:
            unchanged += 1
    updated.sort(key=_order)
    if ts_only:
        log.info("creations", f"Timestamp-only changes (not reported): {sorted(ts_only)}")
    return {"added": added, "removed": removed, "updated": updated, "unchanged": unchanged,
            "timestamp_only": len(ts_only)}


def _yes_no(v):
    return "yes" if v is True else "no" if v is False else json.dumps(v)


def _plain(v):
    return v if isinstance(v, str) else json.dumps(v)


def change_text(c):
    parts = []
    if "version" in c and show_version(c["version"]["old"]) == show_version(c["version"]["new"]):
        parts.append(f"re-uploaded (same version {show_version(c['version']['new']) or '(none)'})")
    elif "version" in c:
        parts.append(f"version {show_version(c['version']['old']) or '(none)'} -> "
                     f"{show_version(c['version']['new']) or '(none)'}")
    if "title" in c:
        parts.append(f"renamed from \"{c['title']['old']}\"")
    if "files" in c:
        if c["files"]["added"]:
            parts.append("files added: " + ", ".join(c["files"]["added"]))
        if c["files"]["removed"]:
            parts.append("files removed: " + ", ".join(c["files"]["removed"]))
    if "files_size" in c:
        parts.append(f"size {_plain(c['files_size']['old'])} -> {_plain(c['files_size']['new'])}")
    if "achievement_safe" in c:
        parts.append(f"achievement-friendly {_yes_no(c['achievement_safe']['old'])} -> "
                     f"{_yes_no(c['achievement_safe']['new'])}")
    for key, v in c.items():
        if key not in ("version", "title", "files", "files_size", "achievement_safe"):
            parts.append(f"{key} {_plain(v['old'])} -> {_plain(v['new'])}")
    return "; ".join(parts)


def entry_text(e):
    files = ", ".join(e["files"]) or "(none)"
    return f"{e['title'] or '(no title)'} ({e['id']}) version {show_version(e['version']) or '(none)'}, files: {files}"


def save_copy(raw, path):
    """Writes the catalog's bytes to path: a temporary file in the same folder, then a replace."""
    folder = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".ContentCatalog-", suffix=".tmp", dir=folder)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as e:
        raise CreationsError(f"can't write the saved copy {path}: {e.strerror}. Fix: give --saved a file in a folder "
                             f"you can write to.")
    log.info("creations", f"wrote the saved copy {path} ({len(raw)} bytes)")


def saved_time(path):
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path))
    except (OSError, ValueError, OverflowError):
        return None
