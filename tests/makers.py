# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""Writes the made-up files the tests use: tiny Windows DLL/EXE files (headers, an export table and a version
resource, no code) and tiny Starfield plugins. Nothing here comes from the game or from anyone's mod."""
import struct
import zlib


# ---- Windows program files ------------------------------------------------------------------------------------
def version_block(name="Test Plugin", author="Test Author", plugin_version=1, address=0, structure=0,
                  compatible=(), sfse_required=0, data_version=1, reserved_breaking=0):
    """An SFSEPlugin_Version block (604 bytes), laid out as in sfse PluginAPI.h."""
    b = bytearray(604)
    struct.pack_into("<II", b, 0, data_version, plugin_version)
    b[8:8 + len(name)] = name.encode("latin-1")
    b[264:264 + len(author)] = author.encode("latin-1")
    struct.pack_into("<II", b, 520, address, structure)
    for i, v in enumerate(compatible):
        struct.pack_into("<I", b, 528 + 4 * i, v)
    struct.pack_into("<I", b, 592, sfse_required)
    struct.pack_into("<I", b, 600, reserved_breaking)
    return bytes(b)


def game_version(major, minor, build):
    return (major & 0xFF) << 24 | (minor & 0xFF) << 16 | (build & 0xFFF) << 4


def pe_file(export=None, block=b"", file_version=None, extra=b""):
    """A minimal 64-bit PE: one section holding an export table (export name -> block) and/or a VS_FIXEDFILEINFO,
    plus `extra` bytes (for example a string)."""
    sect_va, sect_raw = 0x1000, 0x400
    body = bytearray()
    exp_rva = exp_size = rsrc_rva = rsrc_size = 0
    if export is not None:
        exp_at = len(body)
        body += bytes(40)
        name_at = len(body)
        body += export + b"\0"
        dll_name_at = len(body)
        body += b"test.dll\0"
        while len(body) % 8:
            body += b"\0"
        block_at = len(body)
        body += block
        funcs_at = len(body)
        body += struct.pack("<I", sect_va + block_at)
        names_at = len(body)
        body += struct.pack("<I", sect_va + name_at)
        ords_at = len(body)
        body += struct.pack("<H", 0) + b"\0\0"
        struct.pack_into("<IIHHIIIIIII", body, exp_at, 0, 0, 0, 0, sect_va + dll_name_at, 1, 1, 1,
                         sect_va + funcs_at, sect_va + names_at, sect_va + ords_at)
        exp_rva, exp_size = sect_va + exp_at, ords_at + 4 - exp_at
    if file_version is not None:
        rsrc_at = len(body)
        a, b_, c, d = file_version
        body += bytes(32)  # stands in for the resource directory before the version data
        body += struct.pack("<IIII", 0xFEEF04BD, 0x10000, a << 16 | b_, c << 16 | d) + bytes(36)
        rsrc_rva, rsrc_size = sect_va + rsrc_at, len(body) - rsrc_at
    body += extra
    while len(body) % 0x200:
        body += b"\0"

    head = bytearray(sect_raw)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, 0x44, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    opt = 0x58
    struct.pack_into("<H", head, opt, 0x20B)
    struct.pack_into("<I", head, opt + 108, 16)
    struct.pack_into("<II", head, opt + 112, exp_rva, exp_size)
    struct.pack_into("<II", head, opt + 112 + 16, rsrc_rva, rsrc_size)
    sh = opt + 240
    head[sh:sh + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", head, sh + 8, len(body), sect_va, len(body), sect_raw)
    return bytes(head) + bytes(body)


def sfse_plugin(**kw):
    extra = kw.pop("extra", b"")
    return pe_file(b"SFSEPlugin_Version", version_block(**kw), extra=extra)


# ---- Starfield plugins -----------------------------------------------------------------------------------------
def sub(sig, data):
    return sig.encode("ascii") + struct.pack("<H", len(data)) + data


def edid(text):
    return sub("EDID", text.encode("latin-1") + b"\0")


def record(sig, fid, subs, flags=0, compress=False):
    body = b"".join(subs)
    if compress:
        body = struct.pack("<I", len(body)) + zlib.compress(body)
        flags |= 0x40000
    return sig.encode("ascii") + struct.pack("<III", len(body), flags, fid) + bytes(8) + body


def group(label, records):
    content = b"".join(records)
    return b"GRUP" + struct.pack("<I", 24 + len(content)) + label.encode("ascii") + struct.pack("<I", 0) + bytes(8) + content


def plugin(flags=0x1, masters=(), groups=()):
    """A plugin: TES4 header (flags: 0x1 master, 0x100 light, 0x400 medium) and top-level groups."""
    subs = [sub("HEDR", struct.pack("<fII", 0.96, 0, 0x800))]
    for m in masters:
        subs += [sub("MAST", m.encode("latin-1") + b"\0"), sub("DATA", bytes(8))]
    return record("TES4", 0, subs, flags=flags) + b"".join(groups)


def quest(fid, name, stages, compress=False):
    return record("QUST", fid, [edid(name)] + [sub("INDX", struct.pack("<HH", s, 0)) for s in stages],
                  compress=compress)


def cndf(fid, name, conditions):
    return record("CNDF", fid, [edid(name)] + [sub("CTDA", struct.pack("<I", c) + bytes(28)) for c in conditions])


def glob(fid, name, value):
    return record("GLOB", fid, [edid(name), sub("FLTV", struct.pack("<f", value))])


# ---- script data: VMAD fields, compiled scripts (.pex) and general BA2 archives ----------------------------------
def _wstr(text):
    b = text.encode("latin-1")
    return struct.pack("<H", len(b)) + b


def vmad_value(ptype, value):
    """A VMAD property value: 1 Object (FormID), 2 String, 3 Int, 4 Float, 5 Bool, 6 Variable (no bytes, as xEdit
    reads it), 7 Struct ([(name, type, value)]), 11-15 arrays of those, 16 array of Variable (a count only), 17 array
    of structs."""
    if ptype == 6:
        return b""
    if ptype == 16:
        return struct.pack("<I", value)
    if ptype == 1:
        return struct.pack("<HhI", 0, -1, value)
    if ptype == 2:
        return _wstr(value)
    if ptype == 3:
        return struct.pack("<i", value)
    if ptype == 4:
        return struct.pack("<f", value)
    if ptype == 5:
        return bytes([1 if value else 0])
    if ptype == 7:
        return struct.pack("<I", len(value)) + b"".join(vmad_property(*m) for m in value)
    if 11 <= ptype <= 15:
        return struct.pack("<I", len(value)) + b"".join(vmad_value(ptype - 10, v) for v in value)
    if ptype == 17:
        return struct.pack("<I", len(value)) + b"".join(vmad_value(7, v) for v in value)
    raise ValueError(ptype)


def vmad_property(name, ptype, value):
    return _wstr(name) + bytes([ptype, 1]) + vmad_value(ptype, value)


def script_entry(name, props):
    return _wstr(name) + b"\x00" + struct.pack("<H", len(props)) + b"".join(vmad_property(*p) for p in props)


def quest_tail(script="", props=(), fragments=(), aliases=()):
    """The part of a quest's VMAD after its scripts, laid out as xEdit's Starfield definitions read it: the fragment
    script (with its properties), fragments [(stage, script name, function name)] and aliases
    [(alias id, [(script name, [(property, type, value)])])]."""
    out = b"\x03" + struct.pack("<H", len(fragments)) + (script_entry(script, props) if script else _wstr(""))
    for stage, sname, fname in fragments:
        out += struct.pack("<HhiB", stage, 0, 0, 0) + _wstr(sname) + _wstr(fname)
    out += struct.pack("<H", len(aliases))
    for alias, entries in aliases:
        out += struct.pack("<HhI", 0, alias, 0) + struct.pack("<HHH", 6, 2, len(entries))
        out += b"".join(script_entry(n, p) for n, p in entries)
    return out


def vmad(scripts, tail=b""):
    """A VMAD field (version 6, object format 2): scripts = [(script name, [(property, type, value)])]. tail is the
    data after the scripts (quest_tail() for a quest's fragment and alias scripts)."""
    out = struct.pack("<HHH", 6, 2, len(scripts))
    for name, props in scripts:
        out += script_entry(name, props)
    return sub("VMAD", out + tail)


_OPS = {"assign": (0x0D, 2, False), "cast": (0x0E, 2, False), "callmethod": (0x17, 3, True),
        "callparent": (0x18, 2, True), "callstatic": (0x19, 3, True), "return": (0x1A, 1, False),
        "propget": (0x1C, 3, False)}


def pex(name, parent="", variables=(), properties=(), functions=()):
    """A tiny compiled Papyrus script (PEX 3.12), made up for the tests.
    variables: [(name, type)]; properties: [(name, type, backing variable)] (auto properties);
    functions: [(name, [(param, type)], [(local, type)], [(op, [arg, ...])])] in the empty state, where an argument
    is "ident:x", "str:text", "int:3" or "None"."""
    strings = []

    def s(text):
        if text not in strings:
            strings.append(text)
        return struct.pack("<H", strings.index(text))

    def val(arg):
        if arg == "None":
            return b"\x00"
        kind, _, text = arg.partition(":")
        if kind == "ident":
            return b"\x01" + s(text)
        if kind == "str":
            return b"\x02" + s(text)
        if kind == "int":
            return b"\x03" + struct.pack("<i", int(text))
        raise ValueError(arg)

    def func(params, locals_, code):
        out = s("None") + s("") + struct.pack("<IB", 0, 0)
        out += struct.pack("<H", len(params)) + b"".join(s(n) + s(t) for n, t in params)
        out += struct.pack("<H", len(locals_)) + b"".join(s(n) + s(t) for n, t in locals_)
        out += struct.pack("<H", len(code))
        for op, args in code:
            num, fixed, variadic = _OPS[op]
            out += bytes([num]) + b"".join(val(a) for a in args[:fixed])
            if variadic:
                out += val(f"int:{len(args) - fixed}") + b"".join(val(a) for a in args[fixed:])
        return out

    obj = s(parent) + s("") + b"\x00" + struct.pack("<I", 0) + s("")
    obj += struct.pack("<H", 0)  # structs
    obj += struct.pack("<H", len(variables)) + b"".join(s(n) + s(t) + struct.pack("<I", 0) + b"\x00\x00"
                                                        for n, t in variables)
    obj += struct.pack("<H", 0)  # guards
    obj += struct.pack("<H", len(properties)) + b"".join(s(n) + s(t) + s("") + struct.pack("<IB", 0, 7) + s(v)
                                                         for n, t, v in properties)
    obj += struct.pack("<H", 1) + s("") + struct.pack("<H", len(functions))
    obj += b"".join(s(n) + func(p, lo, c) for n, p, lo, c in functions)
    body = struct.pack("<H", 0)  # user flags
    body += struct.pack("<H", 1) + s(name) + struct.pack("<I", len(obj) + 4) + obj
    head = struct.pack("<IBBHQ", 0xFA57C0DE, 3, 12, 4, 0) + _wstr(name + ".psc") + _wstr("test") + _wstr("test")
    return head + struct.pack("<H", len(strings)) + b"".join(_wstr(t) for t in strings) + b"\x00" + body


def ba2(files):
    """A general BA2 (version 1, stored, no compression): files = [(stored name, bytes)]. Name hashes are 0."""
    head, rec = 24, 36
    off = head + rec * len(files)
    records, blobs = b"", b""
    for _name, data in files:
        records += struct.pack("<I4sIIQIII", 0, b"pex\0", 0, 0, off + len(blobs), 0, len(data), 0xBAADF00D)
        blobs += data
    names = b"".join(_wstr(n) for n, _ in files)
    return struct.pack("<4sI4sIQ", b"BTDX", 1, b"GNRL", len(files), off + len(blobs)) + records + blobs + names
