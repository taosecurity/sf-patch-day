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
        self.b, self.p, self.empty = data, 0, False

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


def _tail_entry(r, objfmt, version, bare_empty, both_bare=False):
    """One script entry in the fragment section (the fragment script, or an alias script). With a name it is a full
    entry (name, status, properties). With an empty name the two references disagree: Mutagen (ReadEntry and
    WriteEntry) writes the name only, for every entry; xEdit's Starfield definitions do that only for the quest's
    fragment script (wbScriptFragmentsEmptyScriptDecider) and read a full entry everywhere else. bare_empty picks
    the name-only layout; vmad_parts tries the record type's preferred layout first (BARE_FIRST) and falls back to
    the other. both_bare: an entry both layouts read name-only (the quest's fragment script), so it can't make the
    layouts differ."""
    name = r.wstr()
    if not name and not both_bare:
        r.empty = True  # the two layouts can differ only here (vmad_parts' ambiguity check)
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
        out.append(_tail_entry(r, objfmt, version, True, both_bare=True) + ("fragment",))  # both: name-only
        for _ in range(count):
            r.take(8)  # stage, unknown, stage index
            out += [(n, {}, "fragment") for n in _fragment_names(r, 1)]
        for _ in range(r.u16()):  # aliases: the alias, then its own VMAD version, object format and scripts
            r.take(8)
            aversion, aobjfmt = r.u16(), r.u16()
            for _ in range(r.u16()):
                out.append(_tail_entry(r, aobjfmt, aversion, bare_empty) + ("alias",))
    elif sig in ("INFO", "PACK", "SCEN"):
        # One fragment per flag set, counted as xEdit does: only the low 3 bits for PACK (begin, end, change) and
        # the low 2 for INFO and SCEN (begin, end); higher bits have no fragment.
        flags = r.u8() & (7 if sig == "PACK" else 3)
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


# The record types whose fragment section is read with the name-only layout for an empty script name first. A
# quest's empty fragment script is name-only in both references; its alias scripts are name-only in Mutagen's. The
# other types (INFO, PACK, SCEN, PERK, TMLM) are read with xEdit's full entry first.
BARE_FIRST = {"QUST"}


LAYOUT_NAMES = {True: "name-only (as Mutagen writes it)", False: "full entry (as xEdit reads it)"}


def _other_fits(r, start, sig, objfmt, version, bare_empty, extra):
    """True when the other layout of the fragment section also ends at the field's end with a different result."""
    r.p = start
    try:
        other = _tail(r, sig, objfmt, version, not bare_empty)
    except ScriptError:
        return False
    return r.p == len(r.b) and other != extra


def vmad_parts(data, sig, ambiguous=None):
    """(attached, extra, problem): attached = [(script name, {lowercase property name: ("obj", FormID) or
    ("int", n)})] from a VMAD field; extra = the fragment and alias scripts after them, as (name, props, kind);
    problem = why that second part couldn't be read, or None. The attached list failing raises ScriptError.
    The section is read with the record type's preferred layout for an empty script name first (name-only for QUST,
    xEdit's full entry for the others; see _tail_entry and BARE_FIRST) and, when that fails or doesn't end at the
    field's end, with the other one; the two differ only when an entry's name is empty. When neither ends at the
    field's end, the preferred layout's result is kept if it read. When both end at the field's end with different
    results, the preferred one is kept, and the name of the layout used is added to the list ambiguous (if given)."""
    r = _Buf(data)
    version, objfmt = r.u16(), r.u16()
    attached = [_entry(r, objfmt, version) for _ in range(r.u16())]
    start, tries = r.p, []
    for bare_empty in ((True, False) if sig in BARE_FIRST else (False, True)):
        r.p, r.empty = start, False
        try:
            extra = _tail(r, sig, objfmt, version, bare_empty)
        except ScriptError as e:
            tries.append((None, str(e)))
            continue
        if r.p == len(r.b):
            if (ambiguous is not None and not tries and r.empty
                    and _other_fits(r, start, sig, objfmt, version, bare_empty, extra)):
                ambiguous.append(LAYOUT_NAMES[bare_empty])
            return attached, extra, None
        tries.append((extra, None))
    for extra, _problem in tries:  # neither ends at the field's end: the preferred layout's, if it read
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
        self.native = False  # the function's flags have the native bit (0x2): its code is in the game or a DLL


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
                if body.startswith("returns ") and " flags 0x" in body:
                    try:
                        func.native = bool(int(body.rsplit(" flags ", 1)[1].split()[0], 16) & 2)
                    except ValueError:
                        pass
                elif body.startswith("param ") or body.startswith("local "):
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

    @property
    def all_native(self):
        """True when the script has functions (not counting property get and set) and every one is native, as an
        SFSE plugin's script is: its code runs in the plugin's DLL, so there is nothing to read for stages."""
        funcs = [f for f in self.functions if f.state is not None]
        return bool(funcs) and all(f.native for f in funcs)


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
    """Yields (sig, fid, [(script name, props, kind)], top-level group label) for every record of plugin p with a
    VMAD field; kind is "" for an attached script, "fragment" or "alias". A record whose fragment section reads two
    ways is added to stats["ambiguous"] as (sig, fid, layout used)."""
    for sig, fid, flags, start, size, top in p.walk():
        vm = [d for s, d in subrecords(p.body(flags, start, size)) if s == "VMAD"]
        if not vm:
            continue
        ambiguous = []
        try:
            found, extra, problem = vmad_parts(vm[0], sig, ambiguous)
        except ScriptError as e:
            stats["vmad_failed"] += 1
            log.info("scripts", f"{p.path}: {sig} {fid:08X}: {e}")
            continue
        for layout in ambiguous:
            stats.setdefault("ambiguous", []).append((sig, fid, layout))
            log.info("scripts", f"{p.path}: {sig} {fid:08X}: its fragment section reads two ways that both end at the "
                                f"field's end; the {layout} layout was used (the usual one for {sig})")
        if problem:
            stats["tail_failed"] += 1
            log.info("scripts", f"{p.path}: {sig} {fid:08X}: fragment or alias scripts not read: {problem}")
        yield sig, fid, [(n, pr, "") for n, pr in found] + extra, top


def _local_id(fid):
    """The part of a FormID that names the record inside the plugin it comes from (the rest names that plugin)."""
    top = fid >> 24
    return fid & 0xFFF if top == 0xFE else fid & 0xFFFF if top == 0xFD else fid & 0xFFFFFF


def _origin_props(props, origin_of):
    """props with each ("obj", FormID) value as ("obj", (lowercase plugin, local id)), so the values of two plugins
    with different master lists compare; origin_of(fid) names the plugin a FormID belongs to (None: unknown)."""
    out = {}
    for name, v in props.items():
        if v and v[0] == "obj":
            plugin = origin_of(v[1])
            v = ("obj", (plugin.lower() if plugin else None, _local_id(v[1])))
        out[name] = v
    return out


def _master_attached(masters, dirs, folder, wanted):
    """{(origin plugin, local id): {lowercase attached script name: its properties (_origin_props)}, or None when
    unread} for the records in wanted ({(origin plugin, local id): top-level group label}), as the last of the
    masters that holds each record has them: the copy the mod's override replaces. A record no master holds isn't in
    the result. When a master isn't found or can't be read, every wanted record it might hold (all of them when its
    master list is unknown) is None: that master might hold the last copy."""
    out = {}
    tops = {t for t in wanted.values()}
    if tops & {"CELL", "WRLD"}:
        tops |= {"CELL", "WRLD"}  # a reference can sit in an interior cell or a worldspace
    for m in masters:
        path = find_plugin(m, list(dirs) + [folder])
        if not path:
            log.info("scripts", f"{m} not found: the attached scripts of the records it might hold can't be compared")
            for k in wanted:
                out[k] = None  # it might hold the last copy: can't tell, whatever an earlier master had
            continue
        can_hold = None  # the plugins whose records this master can override (unknown until its header is read)
        try:
            with Plugin(path, dirs) as mp:
                can_hold = {x.lower() for x in mp.masters} | {m.lower()}

                def origin_of(f, mp=mp, m=m):
                    return m if mp.is_own(f) else mp.master_of(f)
                for top in sorted(tops):
                    for sig, fid, flags, start, size, _t in mp.walk(only_top=top):
                        key = (origin_of(fid), _local_id(fid))
                        if key[0] is None or (key[0].lower(), key[1]) not in wanted:
                            continue
                        names = None
                        vm = [d for s, d in subrecords(mp.body(flags, start, size)) if s == "VMAD"]
                        try:
                            names = ({n.lower(): _origin_props(pr, origin_of) for n, pr in vmad_parts(vm[0], sig)[0]}
                                     if vm else {})
                        except ScriptError as e:
                            log.info("scripts", f"{path}: {sig} {fid:08X}: {e}")
                        out[(key[0].lower(), key[1])] = names
        except (OSError, PluginError) as e:
            log.info("scripts", f"{path}: {e}; the attached scripts of the records it might hold can't be compared")
            for k in wanted:
                if can_hold is None or k[0] in can_hold:
                    out[k] = None  # this master might hold the last copy: can't tell, whatever an earlier one had
    return out


def _named_by(path, dirs):
    """The script names a master plugin's records name (attached, fragment and alias scripts)."""
    out, stats = set(), {"vmad_failed": 0, "tail_failed": 0}
    try:
        with Plugin(path, dirs) as p:
            for _sig, _fid, found, _top in _vmad_walk(p, stats):
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
    mod's own records name it or one of the mod's own scripts extends it or calls it with callstatic (a declared
    type isn't enough; a note lists the scripts taken in this way); in both cases only when no master archive holds
    it and no loose-installed master's records name it."""
    nk = tools.ba2.name_key
    notes, stats = [], {"attached": 0, "own": 0, "vmad_failed": 0, "tail_failed": 0}
    folder = os.path.dirname(os.path.abspath(mod_path))
    base = os.path.splitext(os.path.basename(mod_path))[0]
    mod = os.path.basename(mod_path)
    attached = {}  # lowercase script name -> [(record sig, fid, is master record, props, kind)]
    shown_name = {}
    top_of = {}  # FormID of a master record the mod overrides -> its top-level group label
    try:
        with Plugin(mod_path, dirs) as p:
            for sig, fid, found, top in _vmad_walk(p, stats):
                if not p.is_own(fid):
                    top_of[fid] = top
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

        # Loose scripts one of the mod's own scripts extends (its parent) or calls with callstatic. A declared type
        # (a variable, property, local or cast) isn't enough: a script can hold another mod's object without being
        # part of that mod.
        reached, via_code = set(), set()

        def loose_is_mods(k):
            if not shared:
                return True  # everything under the mod's own folder ships with it
            if k in master_archive_keys or k in master_named:
                return False  # someone's loose copy of a master script: can't tell whose
            return (k in named or k in reached) if _ns(k) in GENERIC_NS else _ns(k) in mod_ns

        def take_loose(k):  # loose beats archive: the mod's loose copy is the one the game reads
            if shared and _ns(k) in GENERIC_NS and k not in named and k not in own:
                via_code.add(k)  # taken in only because the mod's code extends or calls it
            lib.add_loose(k, loose_keys[k], (mod, "loose", scripts_root))
            own.add(k)

        for k in sorted(loose_keys):
            if loose_is_mods(k) and (not shared or k in named or k in own):
                take_loose(k)
        def code_only(k):  # a bare loose script that would be taken in only through the mod's code (via_code)
            return k in via_code or (shared and k not in own and k in loose_keys and _ns(k) in GENERIC_NS
                                     and k not in named)

        def native_only(k):  # a loose script whose functions are all native (its listing is read to tell)
            if k not in lib.where:
                lib.add_loose(k, loose_keys[k], (mod, "loose", scripts_root))
            s = lib.get(k)
            return s is not None and s.all_native

        def counted(k):  # the mod's own scripts, for the safety limit
            if code_only(k):  # as if read: an all-native one would be left out (see below)
                return k not in via_code and loose_is_mods(k) and not native_only(k)
            return k in own or (k in loose_keys and loose_is_mods(k))

        todo = sorted(own | named)
        done, read = set(), set()
        while todo:
            key = todo.pop(0)
            if key in done:
                continue
            if len(read) >= MAX_SCRIPTS and code_only(key) and key not in via_code and not counted(key):
                # Past the limit, an all-native bare loose script reached only through the mod's code isn't taken
                # in, as when it's read below.
                done.add(key)
                if loose_is_mods(key):
                    log.info("scripts", f"{loose_keys[key]}: every function is native (a DLL's script): left out "
                                        f"past the safety limit, not counted as {mod}'s")
                continue
            if len(read) >= MAX_SCRIPTS and counted(key):
                # Only the mod's own scripts count; the scripts the unread ones reference aren't found, hence
                # "at least". The unread ones still count as the mod's for ownership (not for analysis); a bare
                # one reached only through code isn't named by any record, so it's counted only.
                unread = sorted({k for k in todo + [key] if k not in done and counted(k)})
                for k in unread:
                    if k not in own and not code_only(k):
                        lib.add_loose(k, loose_keys[k], (mod, "loose", scripts_root))
                        own.add(k)
                log.info("scripts", f"safety limit: {MAX_SCRIPTS} script(s) read; {len(unread)} more of {mod}'s own "
                                    f"weren't read, but still count as {mod}'s for the records they're attached to")
                notes.append(f"stopped after {MAX_SCRIPTS} of your mod's own scripts; at least {len(unread)} more "
                             f"weren't read (a safety limit)")
                break
            done.add(key)
            if key in loose_keys and key not in own and loose_is_mods(key):
                take_loose(key)
            if key not in own:
                continue
            s = lib.get(key)
            if key in via_code and s is not None and s.all_native:
                # A bare loose script taken in only through the mod's code whose functions are all native (an SFSE
                # plugin's script): another mod's, with no code to read. It isn't counted as the mod's.
                via_code.discard(key)
                own.discard(key)
                log.info("scripts", f"{loose_keys[key]}: every function is native (a DLL's script): left out, not "
                                    f"read as {mod}'s")
                continue
            read.add(key)
            if s is None:
                continue
            code_refs = {s.parent}  # the references that make a bare loose script the mod's own
            refs = set(s.types.values()) | set(s.props.values())
            for f in s.functions:
                refs |= set(f.types.values())
                code_refs |= {_ident(a[0]) for op, a in f.code if op == "callstatic" and a}
            for t in sorted(r for r in refs | code_refs if r and is_script_type(r)):
                k = script_key(t, nk)
                if k in loose_keys and t in code_refs:
                    reached.add(k)
                if k not in done and (k in own or (k in loose_keys and loose_is_mods(k))):
                    todo.append(k)
        master_keys = master_archive_keys - own  # the scripts whose winning copy is a master's
        found_own = set(own)  # whose scripts: every own script found, read or not (ownership in _stage_calls)
        own = read  # what's analyzed: the scripts actually read
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
        if via_code:
            shown = sorted(os.path.splitext(os.path.relpath(loose_keys[k], scripts_root))[0].replace(os.sep, ":")
                           .replace("/", ":") for k in via_code)
            more = f" and {len(shown) - 20} more" if len(shown) > 20 else ""
            notes.append(f"{len(shown)} loose script(s) in {scripts_root} with no namespace (or Fragments:) were read "
                         f"as your mod's own because your scripts extend them or call them with callstatic: "
                         f"{', '.join(shown[:20])}{more}")
        def masters_have(asked):
            """The (sig, fid, lowercase script name) in asked ({(sig, fid, name): {property name: the mod's value}},
            the properties its stage calls read) whose script the master's copy of the record already has attached,
            with the same values for those properties: the master put it there, so its stages aren't the mod's
            doing. A changed property (another quest or stage) makes them the mod's."""
            wanted = {}
            for sig, fid, _n in asked:
                if master_of(fid):
                    wanted[(master_of(fid).lower(), _local_id(fid))] = top_of.get(fid, sig)
            copies = _master_attached([m for m in masters if m.lower() != mod.lower()], dirs, folder, wanted)
            out = set()
            for sig, fid, n in sorted(asked):
                key = (master_of(fid).lower(), _local_id(fid)) if master_of(fid) else None
                names = copies.get(key)
                mine = _origin_props(asked[(sig, fid, n)], lambda f: master_of(f) or mod)
                changed = sorted(pn for pn in mine if names and n in names and names[n].get(pn) != mine[pn])
                if names is not None and n in names and not changed:
                    out.add((sig, fid, n))
                    log.info("scripts", f"{shown_name[n]} on {sig} {fid:08X}: the master's copy of the record has it "
                                        f"too; its stages aren't credited to {mod}")
                else:
                    why = ("no master's copy of the record was found" if key not in copies else
                           "the master's copy can't be read" if names is None else
                           "your mod added it to the record" if n not in names else
                           f"your mod changed its propert{'y' if len(changed) == 1 else 'ies'} {', '.join(changed)}")
                    log.info("scripts", f"{shown_name[n]} on {sig} {fid:08X}: {why}; its stages are credited to {mod}")
            return out

        quests = _stage_calls(lib, attached, shown_name, nk, master_of, found_own, masters_have)
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
        two_ways = {}  # (sig, layout) -> FormIDs, one note each with at most 20 listed (the log has them all)
        for sig, fid, layout in stats.get("ambiguous", []):
            two_ways.setdefault((sig, layout), []).append(fid)
        for (sig, layout), fids in sorted(two_ways.items()):
            more = f" and {len(fids) - 20} more" if len(fids) > 20 else ""
            notes.append(f"the fragment scripts of {len(fids)} {sig} record(s) can be read two ways; the {layout} "
                         f"layout was used, the usual one for {sig}: {', '.join(f'{f:08X}' for f in fids[:20])}{more}")
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


def _stage_calls(lib, attached, shown_name, nk, master_of, own, masters_have=None):
    """SetStage / SetCurrentStageID calls on master quests, per record the script is attached to. A quest or stage
    passed down through the script's own functions (Step(RI01, 100) calling akQuest.SetStage(aiStage)) is followed
    up to MAX_DEPTH calls deep. A master's script (not the mod's own copy) on a master record the mod overrides is
    the master's doing, not the mod's: its fragment and alias scripts are skipped, and so are its attached scripts
    when masters_have({(sig, fid, script): {property: value}}) says the master's copy of the record has that script
    too, with the same values for the properties its stage calls read."""
    quests, found = {}, {}
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
        found[sname] = pairs
    # A master's attached script on an overridden master record: ask whether the master's copy has it too.
    # With the properties its stage calls read: when the mod changed one, the stages are the mod's.
    asked = {}
    for sname in attached:
        if not found[sname] or script_key(shown_name[sname], nk) in own:
            continue
        used = {x[1] for _by, q, st in found[sname] for x in (q, st) if x and x[0] == "prop"}
        for sig, fid, is_master, props, kind in attached[sname]:
            if is_master and not kind:
                asked[(sig, fid, sname)] = {pn: props.get(pn) for pn in sorted(used)}
    masters_own = masters_have(asked) if asked and masters_have else set()
    for sname in sorted(attached):
        pairs = found[sname]
        mine = script_key(shown_name[sname], nk) in own
        for sig, fid, is_master, props, kind in attached[sname]:
            if kind and is_master and not mine:
                continue  # a master's own fragment or alias script, kept in the mod's copy of the master record
            if (sig, fid, sname) in masters_own:
                continue  # a master's attached script that the master's copy of the record has too
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
