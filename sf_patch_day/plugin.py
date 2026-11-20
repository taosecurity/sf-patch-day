# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""Reads Starfield plugins (.esm/.esp/.esl) just enough for drift: the header, every record's type, FormID and
flags, and the body of the records asked for. Read-only."""
import mmap
import os
import struct
import zlib

from . import log


class PluginError(Exception):
    """The plugin is damaged or isn't a Starfield plugin."""


class PluginReadError(PluginError):
    """The plugin file can't be opened or read (missing, locked by another program, no permission)."""


def subrecords(data):
    out, i, big = [], 0, None
    while i + 6 <= len(data):
        sig = data[i:i + 4].decode("latin1")
        size = struct.unpack_from("<H", data, i + 4)[0]
        i += 6
        if big is not None:
            size, big = big, None
        chunk = data[i:i + size]
        i += size
        if sig == "XXXX":
            if len(chunk) != 4:
                raise PluginError("a record has a damaged XXXX size field (the plugin is damaged)")
            big = struct.unpack("<I", chunk)[0]
            continue
        out.append((sig, chunk))
    return out


def read_header(path):
    """(header flags, masters) from the TES4 record only."""
    try:
        with open(path, "rb") as f:
            head = f.read(24)
            if len(head) < 24 or head[:4] != b"TES4":
                raise PluginError(f"{path}: not a Starfield plugin (no TES4 header)")
            size, flags = struct.unpack_from("<II", head, 4)
            subs = subrecords(f.read(size))
    except struct.error as e:
        raise PluginError(f"{path}: damaged header ({e})")
    except OSError as e:
        raise PluginReadError(f"{path}: {e.strerror or e}")
    masters = [d.rstrip(b"\0").decode("latin1") for s, d in subs if s == "MAST"]
    return flags, masters


LIGHT, MEDIUM = 0x100, 0x400
DELETED, COMPRESSED = 0x20, 0x40000

# Starfield's Game.GetFormFromFile only finds forms the game keeps in memory at all times, so an in-game version
# check should probe the plugin's newest record of one of these types, in its own top-level group. Editor-only
# records (RFGP, LAYR) and records inside cells (REFR, NAVM) are never found that way.
PROBE_TYPES = {"QUST", "GLOB", "KYWD", "FLST", "MISC", "WEAP"}


def id_mask(flags):
    """GetFormFromFile takes 12 bits for a light plugin, 16 for a medium one, 24 for a full one."""
    return 0xFFF if flags & LIGHT else 0xFFFF if flags & MEDIUM else 0xFFFFFF


def find_plugin(name, dirs):
    """The first <dir>\\<name> that exists, or None."""
    for d in dirs:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


class Plugin:
    def __init__(self, path, search_dirs=()):
        """search_dirs: where to look for its masters (to tell full, medium and light masters apart)."""
        self.path = path
        self.flags, self.masters = read_header(path)
        self.mask = id_mask(self.flags)
        # A plugin's records point at masters in three ways: full masters by their place among the full masters,
        # light masters as FE + place among the light masters, medium masters as FD + place among the medium
        # masters. A plugin's own new records use the same scheme, after its masters. Some tools (Mutagen 0.54.4)
        # number own records by the count of full masters only; the game loads both, so both are accepted.
        self.full, self.light, self.medium, self.unknown = [], [], [], []
        dirs = list(search_dirs) + [os.path.dirname(path)]
        for m in self.masters:
            mp = find_plugin(m, dirs)
            mflags = 0
            if mp:
                try:
                    mflags = read_header(mp)[0]
                except PluginError:
                    mp = None
            if not mp:
                self.unknown.append(m)
            (self.light if mflags & LIGHT else self.medium if mflags & MEDIUM else self.full).append(m)
        if self.unknown:
            log.info("plugin", f"{path}: masters not found, counted as full masters: {self.unknown}")
        self.own_index = len(self.full)
        self.own_light = 0xFE000 | len(self.light) if self.flags & LIGHT else None
        self.own_medium = 0xFD00 | len(self.medium) if self.flags & MEDIUM and not self.flags & LIGHT else None
        # Mapped, not read: Starfield.esm is about 1.5 GB.
        self._file = open(path, "rb")
        try:
            self.data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as e:
            self._file.close()
            raise PluginReadError(f"{path}: can't be read ({e})")
        log.info("plugin", f"read {path}: {len(self.data):,} bytes, flags {self.flags:#x}, masters {self.masters}")

    def close(self):
        self.data.close()
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def walk(self):
        """Yields (sig, form ID, flags, body start, body size, top-level group label) for every record."""
        b = self.data
        try:
            i = 24 + struct.unpack_from("<I", b, 4)[0]
            while i < len(b):
                if b[i:i + 4] != b"GRUP":
                    raise PluginError(f"{self.path}: expected a group at byte {i} (damaged)")
                top_size = struct.unpack_from("<I", b, i + 4)[0]
                top = b[i + 8:i + 12].decode("latin1")
                if top_size < 24 or i + top_size > len(b):
                    raise PluginError(f"{self.path}: group at byte {i} runs past the end (damaged)")
                stack = [(i + 24, i + top_size)]
                while stack:
                    j, end = stack.pop()
                    while j < end:
                        sig = b[j:j + 4]
                        rsize = struct.unpack_from("<I", b, j + 4)[0]
                        if sig == b"GRUP":
                            if rsize < 24:
                                raise PluginError(f"{self.path}: empty group header at byte {j} (damaged)")
                            stack.append((j + rsize, end))
                            j, end = j + 24, j + rsize
                            continue
                        flags, fid = struct.unpack_from("<II", b, j + 8)
                        yield sig.decode("latin1"), fid, flags, j + 24, rsize, top
                        j += 24 + rsize
                i += top_size
        except struct.error as e:
            raise PluginError(f"{self.path}: damaged record table ({e})")

    def body(self, flags, start, size):
        data = self.data[start:start + size]
        if flags & COMPRESSED:
            try:
                return zlib.decompress(data[4:])
            except zlib.error as e:
                raise PluginError(f"{self.path}: a compressed record at byte {start} won't unpack ({e})")
        return data

    def is_own(self, fid):
        return (fid >> 24 == self.own_index
                or (self.own_light is not None and fid >> 12 == self.own_light)
                or (self.own_medium is not None and fid >> 16 == self.own_medium))

    def master_of(self, fid):
        """The master file a record that isn't the plugin's own belongs to, or None."""
        top = fid >> 24
        if top == 0xFE:
            i = (fid >> 12) & 0xFFF
            return self.light[i] if i < len(self.light) else None
        if top == 0xFD:
            i = (fid >> 16) & 0xFF
            return self.medium[i] if i < len(self.medium) else None
        return self.full[top] if top < len(self.full) else None

    def scan(self, want_edids=(), only_types=None):
        """(highest own FormID over all records, probe FormID, {lowercase editor id: (sig, form id, body)}).
        only_types: when every wanted record's type is known, only records of those types are unpacked (fast on
        Starfield.esm)."""
        want = {e.lower() for e in want_edids}
        found, max_own, probe = {}, 0, 0
        for sig, fid, flags, start, size, top in self.walk():
            if self.is_own(fid):
                max_own = max(max_own, fid & 0xFFFFFF)
                if sig in PROBE_TYPES and top == sig and not flags & DELETED:
                    probe = max(probe, fid & 0xFFFFFF)
            if not want or (only_types and sig not in only_types):
                continue
            body = self.body(flags, start, size)
            edid = editor_id(body)
            if edid and edid.lower() in want:
                found[edid.lower()] = (sig, fid, body)
        return max_own, probe, found

    def overrides(self):
        """[(master, sig, form id, editor id or None)] for every record that changes a master's record."""
        out = []
        for sig, fid, flags, start, size, _top in self.walk():
            if self.is_own(fid):
                continue
            out.append((self.master_of(fid), sig, fid, editor_id(self.body(flags, start, size))))
        return out

    def probe_ids(self):
        max_own, probe, _ = self.scan()
        return probe & self.mask, max_own & self.mask

    def low(self, fid):
        """Low FormID for an own record; '<index>:<id>' for a record that lives in a master (an override)."""
        if self.is_own(fid):
            return f"{fid & self.mask:06X}"
        return f"{fid >> 24:02X}:{fid & 0xFFFFFF:06X}"


def editor_id(body):
    if not body.startswith(b"EDID") or len(body) < 6:
        return None
    n = struct.unpack_from("<H", body, 4)[0]
    return body[6:6 + n].rstrip(b"\0").decode("latin1") or None
