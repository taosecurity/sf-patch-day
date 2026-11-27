# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""Reads the few things sf-patch-day needs from Windows program files (PE format), without running them:

- a named export's file offset (SFSE plugins export a data block called SFSEPlugin_Version), the export names, and
- the file version from the version resource (VS_FIXEDFILEINFO), for Starfield.exe and sfse_loader.exe, and
- the names a DLL imports (the import and delay-load tables), for the risk evidence.

It reads headers, the export and import tables and the resource section only. No code is read, run or kept.
"""
import struct


MAX_IMPORT_DLLS = 4096  # import descriptors read per directory
MAX_THUNKS = 20000      # functions read per imported DLL
MAX_IMPORT_NAME = 256   # bytes in a DLL or function name


class PEError(Exception):
    """The file isn't a Windows program file this reader understands."""


class PE:
    def __init__(self, data, name="file"):
        """data: bytes or a read-only mmap of the whole file."""
        self.data, self.name = data, name
        try:
            self._parse()
        except (struct.error, IndexError, ValueError) as e:
            raise PEError(f"{name}: damaged or not a Windows program file ({e})")

    def _parse(self):
        d = self.data
        if d[:2] != b"MZ":
            raise PEError(f"{self.name}: not a Windows program file (no MZ header)")
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise PEError(f"{self.name}: not a Windows program file (no PE header)")
        nsect = struct.unpack_from("<H", d, pe + 6)[0]
        opt_size = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic not in (0x10B, 0x20B):
            raise PEError(f"{self.name}: unknown optional-header type {magic:#x}")
        self.is64 = magic == 0x20B
        self.image_base = struct.unpack_from("<Q", d, opt + 24)[0] if self.is64 else \
            struct.unpack_from("<I", d, opt + 28)[0]
        dd = opt + (112 if self.is64 else 96)
        n_dirs = struct.unpack_from("<I", d, dd - 4)[0]
        self.dirs = [struct.unpack_from("<II", d, dd + 8 * i) for i in range(min(n_dirs, 16))]
        self.sections = []
        sh = opt + opt_size
        for i in range(nsect):
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, sh + i * 40 + 8)
            self.sections.append((va, max(vsize, rawsize), rawptr, rawsize))

    def off(self, rva):
        """File offset of a relative virtual address, or None when no section holds it."""
        for va, size, raw, rawsize in self.sections:
            if va <= rva < va + size and rva - va < rawsize:
                return rva - va + raw
        return None

    def _cstr(self, offset, limit=512):
        end = self.data.find(b"\0", offset, offset + limit)
        if end < 0:
            raise PEError(f"{self.name}: unterminated name in the export table")
        return bytes(self.data[offset:end])

    def export_offset(self, wanted):
        """File offset of the export called `wanted` (bytes), or None."""
        if len(self.dirs) < 1:
            return None
        exp_rva, _ = self.dirs[0]
        if not exp_rva:
            return None
        e = self.off(exp_rva)
        if e is None:
            return None
        d = self.data
        n_funcs, n_names = struct.unpack_from("<II", d, e + 20)
        funcs, names, ords = struct.unpack_from("<III", d, e + 28)
        names_off, ords_off, funcs_off = self.off(names), self.off(ords), self.off(funcs)
        if None in (names_off, ords_off, funcs_off):
            return None
        for i in range(min(n_names, 65536)):
            name_off = self.off(struct.unpack_from("<I", d, names_off + 4 * i)[0])
            if name_off is not None and self._cstr(name_off) == wanted:
                ordinal = struct.unpack_from("<H", d, ords_off + 2 * i)[0]
                if ordinal >= n_funcs:
                    return None
                return self.off(struct.unpack_from("<I", d, funcs_off + 4 * ordinal)[0])
        return None

    def export_names(self):
        """The set of names in the export table (bytes); empty when there is none. Damaged entries are skipped."""
        if len(self.dirs) < 1 or not self.dirs[0][0]:
            return set()
        e = self.off(self.dirs[0][0])
        if e is None:
            return set()
        d, out = self.data, set()
        try:
            n_names = struct.unpack_from("<I", d, e + 24)[0]
            names_off = self.off(struct.unpack_from("<I", d, e + 32)[0])
            if names_off is None:
                return out
            for i in range(min(n_names, 65536)):
                name_off = self.off(struct.unpack_from("<I", d, names_off + 4 * i)[0])
                if name_off is not None:
                    try:
                        out.add(self._cstr(name_off))
                    except PEError:
                        pass
        except (struct.error, IndexError, ValueError):
            pass
        return out

    def _import_name(self, rva):
        """The NUL-ended name at rva (bytes, 1 to MAX_IMPORT_NAME long), or None when it is outside the file,
        empty or too long."""
        o = self.off(rva) if rva >= 0 else None
        if o is None:
            return None
        end = self.data.find(b"\0", o, o + MAX_IMPORT_NAME + 1)
        if end <= o:
            return None
        return bytes(self.data[o:end])

    def _thunks(self, rva, base=0):
        """([function names, or '#n' for imports by ordinal], entries skipped) for one DLL's name table at rva.
        base is subtracted from the name addresses (the old delay-load form stores addresses, not RVAs)."""
        size = 8 if self.is64 else 4
        fmt, by_ordinal = ("<Q", 1 << 63) if self.is64 else ("<I", 1 << 31)
        names, skipped = [], 0
        for i in range(MAX_THUNKS + 1):
            o = self.off(rva + i * size)
            if i == MAX_THUNKS or o is None or o + size > len(self.data):
                return names, skipped + 1  # too many, or the table runs out of the file before its end mark
            t = struct.unpack_from(fmt, self.data, o)[0]
            if not t:
                return names, skipped
            if t & by_ordinal:
                names.append(f"#{t & 0xFFFF}")
                continue
            name = self._import_name((t & 0x7FFFFFFF) - base + 2)  # 2: the hint before the name
            if name is None:
                skipped += 1
            else:
                names.append(name.decode("latin-1"))
        return names, skipped

    def imports(self):
        """([(DLL name lowercased, [function names or '#n' ordinals], delay-loaded)], entries skipped) from the
        import directory and the delay-load directory. A damaged entry is skipped and counted, never fatal. Limits:
        MAX_IMPORT_DLLS descriptors per directory, MAX_THUNKS functions per DLL, names up to MAX_IMPORT_NAME bytes."""
        out, skipped, d = [], 0, self.data
        for index, delayed in ((1, False), (13, True)):
            if len(self.dirs) <= index or not self.dirs[index][0]:
                continue
            rva, step = self.dirs[index][0], (32 if delayed else 20)
            try:
                for i in range(MAX_IMPORT_DLLS + 1):
                    o = self.off(rva + i * step)
                    if i == MAX_IMPORT_DLLS or o is None or o + step > len(d):
                        skipped += 1
                        break
                    if delayed:
                        attrs, name_rva, _handle, iat, int_rva = struct.unpack_from("<5I", d, o)
                        if not any(struct.unpack_from("<8I", d, o)):
                            break
                        base = 0 if attrs & 1 else self.image_base  # bit 0 clear: the old form with addresses
                        table = int_rva or iat
                    else:
                        oft, _stamp, _chain, name_rva, ft = struct.unpack_from("<5I", d, o)
                        if not (oft or name_rva or ft):
                            break
                        base, table = 0, oft or ft
                    name = self._import_name(name_rva - base)
                    if name is None or not table:
                        skipped += 1
                        continue
                    funcs, bad = self._thunks(table - base, base)
                    skipped += bad
                    out.append((name.decode("latin-1").lower(), funcs, delayed))
            except (struct.error, IndexError, ValueError):
                skipped += 1
        return out, skipped

    def file_version(self):
        """(major, minor, build, revision) from the version resource, or None. Looks for the VS_FIXEDFILEINFO
        signature inside the resource section only."""
        if len(self.dirs) < 3 or not self.dirs[2][0]:
            return None
        rva, size = self.dirs[2]
        start = self.off(rva)
        if start is None:
            return None
        end = min(start + size, len(self.data))
        i = self.data.find(b"\xBD\x04\xEF\xFE", start, end)
        if i < 0 or i + 20 > len(self.data):
            return None
        ms, ls = struct.unpack_from("<II", self.data, i + 8)
        return (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)


# ---- the SFSE plugin version block (sfse PluginAPI.h, struct SFSEPluginVersionData) ----------------------------
ADDR_SIG = 1        # kAddressIndependence_Signatures
ADDR_LIB = 2        # kAddressIndependence_AddressLibrary (the old format)
ADDR_LIB2 = 4       # kAddressIndependence_AddressLibraryV2 (Starfield 1.15.216 and later)
STRUCT_NONE = 1     # kStructureIndependence_NoStructs
STRUCT_1_14_70 = 8  # kStructureIndependence_1_14_70_Layout
BLOCK_SIZE = 604    # up to and including reservedBreaking


def pack_version(major, minor, build):
    """SFSE's MAKE_EXE_VERSION: the form game versions take inside the version block."""
    return (major & 0xFF) << 24 | (minor & 0xFF) << 16 | (build & 0xFFF) << 4


def version_text(v):
    return "" if not v else f"{v >> 24 & 0xFF}.{v >> 16 & 0xFF}.{v >> 4 & 0xFFF}"


def plugin_version_text(v):
    """Authors pick the plugin version number. Many pack it like a game version (0x15070000 is 21.7.0); small
    numbers are shown as they are."""
    return version_text(v) if v > 0xFFFFFF else str(v)


def sfse_block(data, name="file"):
    """The decoded SFSEPlugin_Version block as a dict, or None when the file isn't an SFSE plugin.
    Raises PEError when the file isn't a readable program file at all."""
    pe = PE(data, name)
    try:
        o = pe.export_offset(b"SFSEPlugin_Version")
    except (struct.error, IndexError, ValueError) as e:
        raise PEError(f"{name}: damaged export table ({e})")
    if o is None:
        return None
    if o + BLOCK_SIZE > len(data):
        raise PEError(f"{name}: the SFSEPlugin_Version block runs past the end of the file (damaged)")
    dv, pv = struct.unpack_from("<II", data, o)
    text = lambda a, b: bytes(data[o + a:o + b]).split(b"\0")[0].decode("latin-1")  # noqa: E731
    addr, struct_ind = struct.unpack_from("<II", data, o + 520)
    compat = [v for v in struct.unpack_from("<16I", data, o + 528) if v]
    se_req = struct.unpack_from("<I", data, o + 592)[0]
    reserved_breaking = struct.unpack_from("<I", data, o + 600)[0]
    return {"data_version": dv, "plugin_version": pv, "name": text(8, 264), "author": text(264, 520),
            "address": addr, "structure": struct_ind, "compatible": compat, "sfse_required": se_req,
            "reserved_breaking": reserved_breaking}


def mentions_address_library(data):
    """True when the file holds the text 'versionlib' (the Address Library file name), plain or UTF-16."""
    return data.find(b"versionlib") >= 0 or data.find("versionlib".encode("utf-16-le")) >= 0
