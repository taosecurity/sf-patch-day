# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""drift init's script part: what a mod's compiled scripts use in its masters.

It reads the scripts the mod's records name (the plugin's VMAD fields: attached, fragment and alias scripts) and the
mod's own compiled scripts (.pex, loose under Scripts\\ next to the plugin, or in the mod's own archives
`<Mod> - *.ba2`), with sf-pex-tools. analyze() says which copy of a script counts as the mod's.
From their code it finds:

- every master script function they call (callmethod, callstatic, callparent), found in the script that defines it
  (a function a script inherits is listed under the parent that defines it), with the number of arguments;
- every SetStage / SetCurrentStageID call on a quest that lives in a master, when the quest comes from a script
  property the mod's plugin fills (or from the script's own quest, when the mod attaches it to a master quest),
  with the stage number when it is a constant or an Int property the plugin fills.

Master scripts are found in the masters' own archives (`<Master> - *.ba2`, general archives only) in the search
folders. Nothing is written; only the Data folder (and --plugin-dir folders) and the mod's own folder are read.
"""
import os
import struct

from . import log
from .plugin import Plugin, PluginError, editor_id, find_plugin, subrecords

STAGE_FUNCS = {"setstage", "setcurrentstageid"}
# Types that are values, not scripts. Arrays (T[]) and structs (Script#Struct) aren't scripts either.
VALUE_TYPES = {"none", "int", "float", "bool", "string", "var"}
MAX_SCRIPTS = 5000  # a safety stop for the mod's own scripts


class ScriptError(Exception):
    """A script part that can't be read; init notes it and goes on."""


# ---- VMAD: the scripts a plugin attaches to its records, and the property values it fills ------------------------
class _Buf:
    def __init__(self, data):
        self.b, self.p = data, 0

    def take(self, n):
        if self.p + n > len(self.b):
            raise ScriptError("the script data ends early (damaged or a format this tool doesn't know)")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def s32(self):
        return struct.unpack("<i", self.take(4))[0]

    def wstr(self):
        return bytes(self.take(self.u16())).split(b"\0")[0].decode("latin1")


def _object(r, objfmt):
    """(FormID, alias) of an Object property value."""
    if objfmt == 1:
        fid, alias, _ = struct.unpack("<IhH", r.take(8))
    else:
        _, alias, fid = struct.unpack("<HhI", r.take(8))
    return fid, alias


def _value(r, ptype, objfmt, version):
    """One property value. An Object (no alias) gives ("obj", FormID), an Int ("int", n); others are skipped."""
    if ptype == 1:
        fid, alias = _object(r, objfmt)
        return ("obj", fid) if alias == -1 else None
    if ptype == 2:
        r.wstr()
    elif ptype == 3:
        return ("int", r.s32())
    elif ptype in (4,):
        r.take(4)
    elif ptype == 5:
        r.take(1)
    elif ptype == 6:  # Variable: no value bytes (as xEdit reads it; the Creation Kit can't fill a Var property)
        pass
    elif ptype == 16:  # array of Variable: an element count and nothing else (as xEdit reads it)
        r.u32()
    elif ptype == 7:  # struct: its members are properties
        for _ in range(r.u32()):
            _property(r, objfmt, version)
    elif ptype in (11, 12, 13, 14, 15):
        size = {11: 8, 13: 4, 14: 4, 15: 1}.get(ptype)
        for _ in range(r.u32()):
            r.wstr() if ptype == 12 else r.take(size)
    elif ptype == 17:  # array of structs
        for _ in range(r.u32()):
            for _ in range(r.u32()):
                _property(r, objfmt, version)
    elif ptype != 0:
        raise ScriptError(f"script property type {ptype} isn't known to this tool")
    return None


def _property(r, objfmt, version):
    name, ptype = r.wstr(), r.u8()
    if version >= 4:
        r.u8()  # status
    return name, _value(r, ptype, objfmt, version)


def _entry(r, objfmt, version, name=None):
    """(script name, {lowercase property name: value}) of one script entry (name, status, properties)."""
    name = r.wstr() if name is None else name
    if version >= 4:
        r.u8()  # status
    props = {}
    for _ in range(r.u16()):
        pname, val = _property(r, objfmt, version)
        if val is not None:
            props[pname.lower()] = val
    return name, props


def _fragment_names(r, count):
    for _ in range(count):
        r.take(1)
        yield r.wstr()
        r.wstr()  # the fragment's function name


def _tail_entry(r, objfmt, version, bare_empty):
    """One script entry in the fragment section (the fragment script, or an alias script). With a name it is a full
    entry (name, status, properties). With an empty name the two references disagree: Mutagen (ReadEntry and
    WriteEntry) writes the name only, for every entry; xEdit's Starfield definitions do that only for the quest's
    fragment script (wbScriptFragmentsEmptyScriptDecider) and read a full entry everywhere else. bare_empty picks
    the name-only layout; vmad_parts tries it first and falls back to the full one."""
    name = r.wstr()
    if not name and bare_empty:
        return name, {}
    return _entry(r, objfmt, version, name)


def _tail(r, sig, objfmt, version, bare_empty=True):
    """[(script name, props, "fragment" or "alias")] from the script fragment section after the attached scripts
    (QUST also has alias scripts after it), laid out as xEdit's Starfield definitions read it (bare_empty: see
    _tail_entry). Records of other types, and records without the section, give []."""
    out = []
    if r.p >= len(r.b) or sig not in ("QUST", "INFO", "PACK", "SCEN", "PERK", "TMLM"):
        return out
    r.take(1)  # extra bind data version
    if sig == "QUST":
        count = r.u16()
        out.append(_tail_entry(r, objfmt, version, True) + ("fragment",))  # both references: an empty name is bare
        for _ in range(count):
            r.take(8)  # stage, unknown, stage index
            out += [(n, {}, "fragment") for n in _fragment_names(r, 1)]
        for _ in range(r.u16()):  # aliases: the alias, then its own VMAD version, object format and scripts
            r.take(8)
            aversion, aobjfmt = r.u16(), r.u16()
            for _ in range(r.u16()):
                out.append(_tail_entry(r, aobjfmt, aversion, bare_empty) + ("alias",))
    elif sig in ("INFO", "PACK", "SCEN"):
        flags = r.u8()  # one fragment per flag set
        out.append(_tail_entry(r, objfmt, version, bare_empty) + ("fragment",))
        out += [(n, {}, "fragment") for n in _fragment_names(r, bin(flags).count("1"))]
        if sig == "SCEN":
            for _ in range(r.u16()):  # phase fragments
                r.take(5)
                out += [(n, {}, "fragment") for n in _fragment_names(r, 1)]
    else:  # PERK, TMLM
        out.append(_tail_entry(r, objfmt, version, bare_empty) + ("fragment",))
        for _ in range(r.u16()):
            r.take(4)  # fragment index, unused
            out += [(n, {}, "fragment") for n in _fragment_names(r, 1)]
    return [x for x in out if x[0]]


def vmad_parts(data, sig):
    """(attached, extra, problem): attached = [(script name, {lowercase property name: ("obj", FormID) or
    ("int", n)})] from a VMAD field; extra = the fragment and alias scripts after them, as (name, props, kind);
    problem = why that second part couldn't be read, or None. The attached list failing raises ScriptError.
    The section is read with Mutagen's layout for an empty script name first and, when that fails or doesn't end at
    the field's end, with xEdit's (see _tail_entry); the two differ only when an entry's name is empty."""
    r = _Buf(data)
    version, objfmt = r.u16(), r.u16()
    attached = [_entry(r, objfmt, version) for _ in range(r.u16())]
    start, tries = r.p, []
    for bare_empty in (True, False):
        r.p = start
        try:
            extra = _tail(r, sig, objfmt, version, bare_empty)
        except ScriptError as e:
            tries.append((None, str(e)))
            continue
        if r.p == len(r.b):
            return attached, extra, None
        tries.append((extra, None))
    for extra, _problem in tries:  # neither ends at the field's end: the first one that read, as before
        if extra is not None:
            return attached, extra, None
    return attached, [], tries[0][1]


def vmad_scripts(data):
    """The attached scripts of a VMAD field (vmad_parts' first part)."""
    return vmad_parts(data, None)[0]


# ---- sf-pex-tools listings -------------------------------------------------------------------------------------
def split_args(text):
    """The arguments of a listing code line ("ident:x, str:'a, b', int:3") as a list. Strings are Python reprs,
    so a comma inside one doesn't split it."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("str:", i) and i + 4 < n and text[i + 4] in "'\"":
            q, j = text[i + 4], i + 5
            while j < n and text[j] != q:
                j += 2 if text[j] == "\\" else 1
            j += 1
        else:
            j = text.find(", ", i)
            j = n if j < 0 else j
        out.append(text[i:j])
        i = j + 2 if text.startswith(", ", j) else j + 1 if j < n else n
    return out


class Function:
    def __init__(self, name, state):
        self.name, self.state = name, state
        self.types = {}  # lowercase param/local name -> type
        self.params = []  # lowercase parameter names, in order
        self.code = []  # (op, [args])


class Script:
    """One script object read from a listing."""

    def __init__(self, listing):
        self.name, self.parent = None, ""
        self.types = {}  # lowercase variable name -> type
        self.autovar = {}  # lowercase backing variable -> property name
        self.props = {}  # lowercase property name -> type
        self.functions = []
        self.empty_state = {}  # lowercase function name -> (name, parameter count)
        state, func, prop = None, None, None
        for line in listing:
            body = line.strip()
            ind = len(line) - len(line.lstrip(" "))
            if line.startswith("object ") and self.name is None:
                name, _, parent = line[7:].partition(" extends ")
                self.name, self.parent = name, parent.strip()[1:-1]
            elif ind == 2 and body.startswith("variable "):
                vname, _, rest = body[9:].partition(" : ")
                self.types[vname.lower()] = rest.split("  ")[0]
                func = None
            elif ind == 2 and body.startswith("property "):
                pname, _, rest = body[9:].partition(" : ")
                prop = pname
                self.props[pname.lower()] = rest.split("  ")[0]
                func = None
            elif ind == 4 and body.startswith("autovar ") and prop:
                self.autovar[body[8:].lower()] = prop
            elif ind == 4 and body in ("get", "set") and prop:
                func = Function(f"{prop}.{body}", None)
                self.functions.append(func)
            elif ind == 2 and body.startswith("state "):
                state, func, prop = body[6:].strip("'\""), None, None
            elif ind == 2:
                state, func, prop = None, None, None
            elif ind == 4 and body.startswith("function ") and state is not None:
                func = Function(body[9:], state)
                self.functions.append(func)
                if state == "":
                    self.empty_state[func.name.lower()] = (func.name, 0)
            elif ind >= 6 and func is not None:  # code lines are indented further by their number
                if body.startswith("param ") or body.startswith("local "):
                    vname, _, vtype = body[6:].partition(" : ")
                    func.types[vname.lower()] = vtype
                    if body.startswith("param "):
                        func.params.append(vname.lower())
                    if body.startswith("param ") and func.state == "":
                        n, c = self.empty_state[func.name.lower()]
                        self.empty_state[func.name.lower()] = (n, c + 1)
                elif body[:1].isdigit():
                    _, _, rest = body.partition(" ")
                    op, _, args = rest.partition(" ")
                    func.code.append((op, split_args(args)))


def _ident(arg):
    return arg[6:] if arg.startswith("ident:") else None


def script_key(type_name, name_key):
    """The archive key of a script type: SQ:Parent -> SCRIPTS/SQ/PARENT.PEX."""
    return name_key("scripts/" + type_name.replace(":", "/") + ".pex")


def is_script_type(t):
    return bool(t) and t.lower() not in VALUE_TYPES and not t.endswith("]") and "#" not in t


# ---- where scripts are -------------------------------------------------------------------------------------------
def own_archives(base, folders):
    """The archives that belong to plugin `base` (no extension): `<base> - <name>.ba2` whose <name> has no " - "
    (so `Mod - Part - Main.ba2` belongs to `Mod - Part.esm`, not `Mod.esm`), general archives only, from the first
    folder that holds each name. Console archives (`<base> - Main_xbox.ba2`, `_ps5`) are left out when the plugin
    has a PC archive: a Creations build folder holds both, and the PC game reads only the PC one."""
    pre, seen, out = base.lower() + " - ", set(), []
    for d in folders:
        try:
            names = sorted(os.listdir(d))
        except OSError as e:
            log.info("scripts", f"can't list {d}: {e.strerror or e}")
            continue
        for n in names:
            low = n.lower()
            if not (low.startswith(pre) and low.endswith(".ba2")) or " - " in low[len(pre):-4] or low in seen:
                continue
            path = os.path.join(d, n)
            try:
                with open(path, "rb") as f:
                    head = f.read(12)
            except OSError as e:
                log.info("scripts", f"can't read {path}: {e.strerror or e}")
                continue
            if head[8:12] == b"GNRL":
                seen.add(low)
                out.append(path)
    pc = [p for p in out if not _console(p)]
    if pc and len(pc) < len(out):
        log.info("scripts", f"console archives left out (the PC archive is read): "
                            f"{[os.path.basename(p) for p in out if _console(p)]}")
        return pc
    return out


CONSOLE_SUFFIXES = ("_xbox", "_ps5")


def _console(path):
    return os.path.splitext(os.path.basename(path))[0].lower().endswith(CONSOLE_SUFFIXES)


class Library:
    """Scripts by key, from archives and loose folders, read on demand and kept."""

    def __init__(self, tools):
        self.tools = tools
        self.where = {}  # key -> (origin, stored name, reader)
        self.cache = {}
        self.archives = []
        self.failed = []

    def add_archive(self, path, origin, override=True):
        ba2 = self.tools.ba2
        try:
            a = ba2.Archive(path)
        except (ba2.BA2Error, OSError) as e:
            self.failed.append(f"{path}: {e}")
            return 0
        self.archives.append(a)
        n = 0
        for e in a.entries:
            if not e["name"].lower().endswith(".pex") or e["key"] in a.duplicates:
                continue
            if override or e["key"] not in self.where:
                self.where[e["key"]] = (origin, e["name"], lambda a=a, e=e: (a.check_can_unpack([e]), a.read(e))[1])
                n += 1
        log.info("scripts", f"{path}: {n} script(s) for {origin[0]}")
        return n

    def add_loose(self, key, path, origin):
        def read(path=path):
            with open(path, "rb") as f:
                return f.read()
        self.where[key] = (origin, "scripts/" + os.path.relpath(path, origin[2]).replace("\\", "/"), read)

    def get(self, key):
        """The Script for a key, or None (missing or unreadable; unreadable ones are noted once)."""
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = None
        hit = self.where.get(key)
        if hit is None:
            return None
        origin, stored, read = hit
        ba2 = self.tools.ba2
        try:
            data = read()
            self.cache[key] = Script(self.tools.pex.listing(data, stored, ignore_debug=True))
        except (self.tools.pex.PexError, ba2.EntryError, OSError) as e:  # this one script
            self.failed.append(f"{stored} ({origin[0]}): {e}")
        except ba2.BA2Error as e:  # the whole archive (LZ4 without the lz4 package): said once
            self.failed.append(str(e))
        return self.cache[key]

    def close(self):
        for a in self.archives:
            a.close()


def _loose_index(folder, name_key):
    """(the Scripts folder or None, {key: path}) for every .pex under <folder>\\Scripts. Two files with one key
    (names that differ only in case) are both left out: the tool can't tell which one the game reads."""
    root = None
    try:
        for n in sorted(os.listdir(folder)):
            if n.lower() == "scripts" and os.path.isdir(os.path.join(folder, n)):
                root = os.path.join(folder, n)
                break
    except OSError as e:
        log.info("scripts", f"can't list {folder}: {e.strerror or e}")
    out, twice = {}, set()
    if root:
        for d, dirs, names in os.walk(root):
            dirs.sort()
            for n in sorted(names):
                if n.lower().endswith(".pex"):
                    full = os.path.join(d, n)
                    k = name_key("scripts/" + os.path.relpath(full, root).replace("\\", "/"))
                    (twice.add(k) if k in out else out.__setitem__(k, full))
    for k in twice:
        log.info("scripts", f"{out.pop(k)}: more than one loose file matches this script name; left out")
    return root, out


# ---- the analysis ------------------------------------------------------------------------------------------------
GENERIC_NS = ("", "FRAGMENTS")  # no namespace, or the one every mod's fragment scripts share


def _ns(key):
    """The namespace of a script key: SCRIPTS/SQ/PARENT.PEX -> SQ, SCRIPTS/PARENT.PEX -> ""."""
    parts = key.split("/")
    return parts[1] if len(parts) > 2 else ""


def _shared_folder(folder, dirs):
    """True when the plugin sits in a folder other plugins share (the game's Data folder or a search folder), so its
    Scripts folder holds other mods' loose scripts too."""
    key = os.path.normcase(os.path.abspath(folder))
    return (any(os.path.normcase(os.path.abspath(d or ".")) == key for d in dirs)
            or os.path.isfile(os.path.join(folder, "Starfield.esm")))


def _vmad_walk(p, stats):
    """Yields (sig, fid, [(script name, props, kind)]) for every record of plugin p with a VMAD field; kind is
    "" for an attached script, "fragment" or "alias"."""
    for sig, fid, flags, start, size, _top in p.walk():
        vm = [d for s, d in subrecords(p.body(flags, start, size)) if s == "VMAD"]
        if not vm:
            continue
        try:
            found, extra, problem = vmad_parts(vm[0], sig)
        except ScriptError as e:
            stats["vmad_failed"] += 1
            log.info("scripts", f"{p.path}: {sig} {fid:08X}: {e}")
            continue
        if problem:
            stats["tail_failed"] += 1
            log.info("scripts", f"{p.path}: {sig} {fid:08X}: fragment or alias scripts not read: {problem}")
        yield sig, fid, [(n, pr, "") for n, pr in found] + extra


def _named_by(path, dirs):
    """The script names a master plugin's records name (attached, fragment and alias scripts)."""
    out, stats = set(), {"vmad_failed": 0, "tail_failed": 0}
    try:
        with Plugin(path, dirs) as p:
            for _sig, _fid, found in _vmad_walk(p, stats):
                out |= {n for n, _, _ in found}
    except (OSError, PluginError) as e:
        log.info("scripts", f"{path}: {e}")
    return out


def analyze(mod_path, dirs, tools):
    """(functions, quests, notes, stats).
    functions: {master: {"ba2": archive file name, "scripts": {stored script name: {function: params}}}};
    quests: {(master, FormID in the mod's numbering): {"stages": set, "unknown": bool, "by": set of scripts}}.

    Which copy of a script counts, as in the game: a loose file beats every archive, and a later archive beats an
    earlier one. A script whose winning copy is the mod's own (its archive, or a loose file it ships) is analyzed as
    the mod's, even when a master has a copy too; only scripts whose winning copy is in a master's archive are
    master scripts. When the plugin sits in a shared folder (the Data folder), a loose script there counts as the
    mod's only when its namespace is one the mod uses and no master uses, or (no namespace, or Fragments:) when the
    mod's own records or one of the mod's own scripts name it (as a type, a callstatic or a parent); in both cases
    only when no master archive holds it and no loose-installed master's records name it."""
    nk = tools.ba2.name_key
    notes, stats = [], {"attached": 0, "own": 0, "vmad_failed": 0, "tail_failed": 0}
    folder = os.path.dirname(os.path.abspath(mod_path))
    base = os.path.splitext(os.path.basename(mod_path))[0]
    mod = os.path.basename(mod_path)
    attached = {}  # lowercase script name -> [(record sig, fid, is master record, props, kind)]
    shown_name = {}
    try:
        with Plugin(mod_path, dirs) as p:
            for sig, fid, found in _vmad_walk(p, stats):
                for name, props, kind in found:
                    attached.setdefault(name.lower(), []).append((sig, fid, not p.is_own(fid), props, kind))
                    shown_name.setdefault(name.lower(), name)
            masters = list(p.masters)
            master_of = p.master_of
    except (OSError, PluginError) as e:
        raise ScriptError(f"{e}")
    stats["attached"] = len(attached)
    lib = Library(tools)
    try:
        no_archive = []
        for m in masters:  # later masters load later: their scripts win
            found = own_archives(os.path.splitext(m)[0], dirs)
            for path in found:
                lib.add_archive(path, (m, os.path.basename(path), None))
            if not found and m.lower() != mod.lower():
                no_archive.append(m)
        master_archive_keys = set(lib.where)
        for path in own_archives(base, [folder]):
            lib.add_archive(path, (mod, os.path.basename(path), None))
        # The mod's archive copy of a master script replaces the master's: it's the mod's own script now.
        own = {k for k, v in lib.where.items() if v[0][0] == mod}
        scripts_root, loose_keys = _loose_index(folder, nk)
        named = {script_key(n, nk) for n in attached}
        shared = _shared_folder(folder, dirs)
        master_named, mod_ns = set(), set()
        if shared:
            master_ns, master_named = {_ns(k) for k in master_archive_keys}, set()
            for m in no_archive:  # a master installed loose: the scripts its records name, and their namespaces
                path = find_plugin(m, list(dirs) + [folder])
                if path:
                    master_named |= {script_key(n, nk) for n in _named_by(path, dirs)}
            master_ns |= {_ns(k) for k in master_named}
            mod_ns = {_ns(k) for k in named | own} - master_ns - set(GENERIC_NS)
            log.info("scripts", f"{folder} is shared: loose scripts count as {mod}'s in namespaces {sorted(mod_ns)}"
                                f" and when its records or its own scripts name them (no namespace or Fragments:)")

        reached = set()  # loose scripts one of the mod's own scripts references (a type, a callstatic, a parent)

        def loose_is_mods(k):
            if not shared:
                return True  # everything under the mod's own folder ships with it
            if k in master_archive_keys or k in master_named:
                return False  # someone's loose copy of a master script: can't tell whose
            return (k in named or k in reached) if _ns(k) in GENERIC_NS else _ns(k) in mod_ns

        def take_loose(k):  # loose beats archive: the mod's loose copy is the one the game reads
            lib.add_loose(k, loose_keys[k], (mod, "loose", scripts_root))
            own.add(k)

        for k in sorted(loose_keys):
            if loose_is_mods(k) and (not shared or k in named or k in own):
                take_loose(k)
        todo = sorted(own | named)
        done, read = set(), set()
        while todo:
            key = todo.pop(0)
            if key in done:
                continue
            if len(read) >= MAX_SCRIPTS:
                left = len({k for k in todo + [key] if k in own or k in loose_keys} - done)
                notes.append(f"stopped after {MAX_SCRIPTS} of your mod's own scripts; {left} more weren't read "
                             f"(a safety limit)")
                break
            done.add(key)
            if key in loose_keys and key not in own and loose_is_mods(key):
                take_loose(key)
            if key not in own:
                continue
            read.add(key)
            s = lib.get(key)
            if s is None:
                continue
            refs = set(s.types.values()) | set(s.props.values()) | {s.parent}
            for f in s.functions:
                refs |= set(f.types.values())
                refs |= {_ident(a[0]) for op, a in f.code if op == "callstatic" and a}
            for t in sorted(r for r in refs if r and is_script_type(r)):
                k = script_key(t, nk)
                if k in loose_keys:
                    reached.add(k)
                if k not in done and (k in own or (k in loose_keys and loose_is_mods(k))):
                    todo.append(k)
        master_keys = master_archive_keys - own  # the scripts whose winning copy is a master's
        own = read
        stats["own"] = len([k for k in own if lib.get(k)])
        functions, mismatches, missing, shadowed = {}, set(), set(), set()

        def defining(type_name, fname):
            """(key, Script) of the master script that defines fname for type_name, following parents; ("own",
            None) when the copy that defines it is the mod's own (a changed copy of a master script)."""
            k, depth = script_key(type_name, nk), 0
            while k and depth < 30:
                s = lib.get(k)
                if s is None:
                    return None, None
                if fname.lower() in s.empty_state:
                    return (k, s) if k in master_keys else ("own", None)
                k = script_key(s.parent, nk) if s.parent else None
                depth += 1
            return None, None

        def note_call(owner, type_name, fname, nargs):
            k, s = defining(type_name, fname)
            if k == "own":
                return
            if k is None:
                if script_key(type_name, nk) in master_keys and lib.get(script_key(type_name, nk)):
                    missing.add(f"{owner} calls {type_name}.{fname}(), which no master script defines now")
                return
            origin, stored, _ = lib.where[k]
            if shared and k in loose_keys:
                shadowed.add(stored)
            name, params = s.empty_state[fname.lower()]
            entry = functions.setdefault(origin[0], {}).setdefault(origin[1], {}).setdefault(stored, {})
            entry[name] = params
            if params != nargs:
                mismatches.add(f"{owner} calls {s.name}.{name}() with {nargs} argument(s), but the installed "
                               f"{origin[0]} script takes {params}: rebuild your mod against this game version")

        for key in sorted(own):
            s = lib.get(key)
            if s is None:
                continue
            for f in s.functions:
                for op, a in f.code:
                    if op == "callmethod" and len(a) >= 3:
                        fname, obj = _ident(a[0]), _ident(a[1])
                        if not fname or not obj:
                            continue
                        t = s.name if obj.lower() == "self" else f.types.get(obj.lower()) or s.types.get(obj.lower())
                        if t and is_script_type(t):
                            note_call(s.name, t, fname, len(a) - 3)
                    elif op == "callstatic" and len(a) >= 3 and _ident(a[0]) and _ident(a[1]):
                        note_call(s.name, _ident(a[0]), _ident(a[1]), len(a) - 3)
                    elif op == "callparent" and len(a) >= 2 and _ident(a[0]) and s.parent:
                        note_call(s.name, s.parent, _ident(a[0]), len(a) - 2)
        notes += sorted(mismatches) + sorted(missing)
        if shadowed:
            notes.append(f"{scripts_root} holds loose copies of {len(shadowed)} master script(s) your scripts call "
                         f"({', '.join(sorted(shadowed))}); the game runs those, not the archive copies drift reads, "
                         f"and init can't tell which mod they come from")
        quests = _stage_calls(lib, attached, shown_name, nk, master_of, own)
        # One archive per master in the mods file: keep the one holding the most called scripts.
        out = {}
        for m in sorted(functions):
            ba2s = functions[m]
            pick = sorted(ba2s, key=lambda b: (-len(ba2s[b]), b.lower()))[0]
            out[m] = {"ba2": pick, "scripts": ba2s[pick]}
            for other in sorted(b for b in ba2s if b != pick):
                notes.append(f"{m}: functions in {other} left out ({', '.join(sorted(ba2s[other]))}); the mods file "
                             f"holds one archive per master")
        notes += [f"couldn't read {x}" for x in sorted(set(lib.failed))]
        if stats["vmad_failed"]:
            notes.append(f"the script properties of {stats['vmad_failed']} record(s) couldn't be read (the log says "
                         f"which)")
        if stats["tail_failed"]:
            notes.append(f"the fragment or alias scripts of {stats['tail_failed']} record(s) couldn't be read (the "
                         f"log says which); their attached scripts were read")
        # The mod is never its own master (a plugin that lists itself as a master is damaged).
        out = {m: v for m, v in out.items() if m.lower() != mod.lower()}
        quests = {k: v for k, v in quests.items() if k[0].lower() != mod.lower()}
        return out, quests, notes, stats
    finally:
        lib.close()


MAX_DEPTH = 6  # how many calls deep a quest or stage number is followed through a script's own functions


def _sources(s, f):
    """A function's SetStage calls and its calls to the script's own functions, with each argument's source:
    ("const", n), ("prop", property name), ("self",), ("param", index) or None (not known before the game runs)."""
    alias = {}  # lowercase local -> property name
    for op, a in f.code:
        if op in ("assign", "cast") and len(a) >= 2 and _ident(a[0]) and _ident(a[1]):
            src = _ident(a[1]).lower()
            prop = alias.get(src) or s.autovar.get(src)
            if prop:
                alias[_ident(a[0]).lower()] = prop
        elif op == "propget" and len(a) >= 3 and (_ident(a[1]) or "").lower() == "self" and _ident(a[2]):
            alias[_ident(a[2]).lower()] = _ident(a[0])

    def src(arg):
        if arg.startswith("int:"):
            return ("const", int(arg[4:]))
        ident = (_ident(arg) or "").lower()
        if not ident:
            return None
        if ident == "self":
            return ("self",)
        prop = alias.get(ident) or s.autovar.get(ident)
        if prop:
            return ("prop", prop.lower())
        if ident in f.params:
            return ("param", f.params.index(ident))
        return None
    stage_calls, self_calls = [], []
    for op, a in f.code:
        if op != "callmethod" or len(a) < 3 or not _ident(a[0]):
            continue
        name = _ident(a[0]).lower()
        if name in STAGE_FUNCS:
            stage_calls.append((src(a[1]), src(a[3]) if len(a) >= 4 else None))
        elif (_ident(a[1]) or "").lower() == "self":
            self_calls.append((name, [src(x) for x in a[3:]]))
    return stage_calls, self_calls


def _stage_calls(lib, attached, shown_name, nk, master_of, own):
    """SetStage / SetCurrentStageID calls on master quests, per record the script is attached to. A quest or stage
    passed down through the script's own functions (Step(RI01, 100) calling akQuest.SetStage(aiStage)) is followed
    up to MAX_DEPTH calls deep."""
    quests = {}
    for sname in sorted(attached):
        chain, k, depth = [], script_key(shown_name[sname], nk), 0
        while k and depth < 30:  # the attached script and the parents whose code runs with its properties
            s = lib.get(k)
            if s is None:
                break
            chain.append(s)
            k = script_key(s.parent, nk) if s.parent else None
            depth += 1
        own_funcs = {}  # a call on self finds the child's function first
        for s in chain:
            for f in s.functions:
                if f.state in ("", None) and "." not in f.name:
                    own_funcs.setdefault(f.name.lower(), (s, f))
        info = {}

        def summary(s, f):
            key = (s.name, f.state, f.name)
            if key not in info:
                info[key] = _sources(s, f)
            return info[key]

        def expand(s, f, depth, busy):
            """[(quest source, stage source)] for f and the functions it calls on self, with their parameters
            replaced by the arguments of each call."""
            direct, calls = summary(s, f)
            out = list(direct)
            if depth >= MAX_DEPTH:
                return out
            for name, args in calls:
                hit = own_funcs.get(name)
                if hit is None or (hit[0].name, hit[1].name) in busy:
                    continue
                for q, st in expand(hit[0], hit[1], depth + 1, busy | {(hit[0].name, hit[1].name)}):
                    sub = [args[x[1]] if x and x[0] == "param" and x[1] < len(args) else
                           None if x and x[0] == "param" else x for x in (q, st)]
                    out.append(tuple(sub))
            return out

        pairs = set()
        for s in chain:
            for f in s.functions:
                for q, st in expand(s, f, 0, {(s.name, f.name)}):
                    if q and q[0] in ("prop", "self"):
                        if not (st and st[0] in ("const", "prop")):
                            log.info("scripts", f"{s.name}.{f.name}: a stage of {q[-1]} isn't a constant or a "
                                                f"property ({st}); not listed")
                            st = None
                        pairs.add((s.name, q, st))
        mine = script_key(shown_name[sname], nk) in own
        for sig, fid, is_master, props, kind in attached[sname]:
            if kind and is_master and not mine:
                continue  # a master's own fragment or alias script, kept in the mod's copy of the master record
            for by, q, st in sorted(pairs, key=repr):
                if q[0] == "self":
                    qfid = fid if is_master and sig == "QUST" and kind != "alias" else None
                else:
                    v = props.get(q[1])
                    qfid = v[1] if v and v[0] == "obj" else None
                if qfid is None or master_of(qfid) is None:
                    continue
                stage = None
                if st and st[0] == "const":
                    stage = st[1]
                elif st:
                    v = props.get(st[1])
                    stage = v[1] if v and v[0] == "int" else None
                e = quests.setdefault((master_of(qfid), qfid), {"stages": set(), "unknown": False, "by": set()})
                e["by"].add(by)
                if stage is None or stage > 65535:  # a stage number is 0 to 65535: a bigger one isn't a stage
                    e["unknown"] = True
                elif stage >= 0:  # a negative number is a "no stage" marker that never reaches SetStage
                    e["stages"].add(stage)
    return quests


def quest_edids(quests, mod_path, dirs):
    """{(master, fid): Editor ID or None} for the master quests, read from each master's QUST group."""
    out = {k: None for k in quests}
    by_master = {}
    for master, fid in quests:
        by_master.setdefault(master, []).append(fid)
    for master in sorted(by_master):
        path = find_plugin(master, list(dirs) + [os.path.dirname(os.path.abspath(mod_path))])
        if not path:
            log.info("scripts", f"{master} not found: its quests can't be named")
            continue
        try:
            with Plugin(path, dirs) as mp:
                want = {f & mp.mask: f for f in by_master[master]}
                for sig, fid, flags, start, size, _top in mp.walk(only_top="QUST"):
                    if sig == "QUST" and mp.is_own(fid) and (fid & mp.mask) in want:
                        out[(master, want[fid & mp.mask])] = editor_id(mp.body(flags, start, size))
        except (OSError, PluginError) as e:
            log.info("scripts", f"{path}: {e}")
    return out
