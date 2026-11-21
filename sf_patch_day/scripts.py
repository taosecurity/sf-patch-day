# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""drift init's script part: what a mod's compiled scripts use in its masters.

It reads the scripts attached to the mod's records (the plugin's VMAD fields) and the mod's own compiled scripts
(.pex, loose under Scripts\\ next to the plugin, or in the mod's own archives `<Mod> - *.ba2`), with sf-pex-tools.
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


def vmad_scripts(data):
    """[(script name, {lowercase property name: ("obj", FormID) or ("int", n)})] from a VMAD field. Only the list
    of attached scripts is read; quest fragments and alias scripts after it are not."""
    r = _Buf(data)
    version, objfmt = r.u16(), r.u16()
    out = []
    for _ in range(r.u16()):
        name = r.wstr()
        if version >= 4:
            r.u8()  # status
        props = {}
        for _ in range(r.u16()):
            pname, val = _property(r, objfmt, version)
            if val is not None:
                props[pname.lower()] = val
        out.append((name, props))
    return out


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
    folder that holds each name."""
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
    return out


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
def analyze(mod_path, dirs, tools):
    """(functions, quests, notes, stats).
    functions: {master: {"ba2": archive file name, "scripts": {stored script name: {function: params}}}};
    quests: {(master, FormID in the mod's numbering): {"stages": set, "unknown": bool, "by": set of scripts}}."""
    nk = tools.ba2.name_key
    notes, stats = [], {"attached": 0, "own": 0, "vmad_failed": 0}
    folder = os.path.dirname(os.path.abspath(mod_path))
    base = os.path.splitext(os.path.basename(mod_path))[0]
    attached = {}  # lowercase script name -> [(record sig, fid, is master record, props)]
    shown_name = {}
    try:
        with Plugin(mod_path, dirs) as p:
            for sig, fid, flags, start, size, _top in p.walk():
                body = p.body(flags, start, size)
                vm = [d for s, d in subrecords(body) if s == "VMAD"]
                if not vm:
                    continue
                try:
                    found = vmad_scripts(vm[0])
                except ScriptError as e:
                    stats["vmad_failed"] += 1
                    log.info("scripts", f"{sig} {fid:08X}: {e}")
                    continue
                for name, props in found:
                    attached.setdefault(name.lower(), []).append((sig, fid, not p.is_own(fid), props))
                    shown_name.setdefault(name.lower(), name)
            masters = list(p.masters)
            master_of = p.master_of
    except (OSError, PluginError) as e:
        raise ScriptError(f"{e}")
    stats["attached"] = len(attached)
    lib = Library(tools)
    try:
        for m in masters:  # later masters load later: their scripts win
            mbase = os.path.splitext(m)[0]
            for path in own_archives(mbase, dirs):
                lib.add_archive(path, (m, os.path.basename(path), None))
        master_keys = set(lib.where)
        mod = os.path.basename(mod_path)
        for path in own_archives(base, [folder]):
            lib.add_archive(path, (mod, os.path.basename(path), None))
        scripts_root, loose_keys = _loose_index(folder, nk)
        own = {k for k, v in lib.where.items() if v[0][0] == mod}
        # Loose files win over archives in the game, so a loose copy of one of the mod's scripts is the one read.
        todo = sorted(own | {script_key(n, nk) for n in attached})
        done = set()
        while todo and len(done) < MAX_SCRIPTS:
            key = todo.pop(0)
            if key in done:
                continue
            done.add(key)
            if key in loose_keys and key not in master_keys:
                lib.add_loose(key, loose_keys[key], (mod, "loose", scripts_root))
                own.add(key)
            if key not in own:
                continue
            s = lib.get(key)
            if s is None:
                continue
            refs = set(s.types.values()) | set(s.props.values()) | {s.parent}
            for f in s.functions:
                refs |= set(f.types.values())
                refs |= {_ident(a[0]) for op, a in f.code if op == "callstatic" and a}
            for t in sorted(r for r in refs if r and is_script_type(r)):
                k = script_key(t, nk)
                if k not in done and k not in master_keys and (k in loose_keys or k in own):
                    todo.append(k)
        stats["own"] = len([k for k in own if lib.get(k)])
        functions, mismatches, missing = {}, set(), set()

        def defining(type_name, fname):
            """(key, Script) of the master script that defines fname for type_name, following parents."""
            k, depth = script_key(type_name, nk), 0
            while k and depth < 30:
                s = lib.get(k)
                if s is None:
                    return None, None
                if fname.lower() in s.empty_state:
                    return (k, s) if k in master_keys else (None, None)
                k = script_key(s.parent, nk) if s.parent else None
                depth += 1
            return None, None

        def note_call(owner, type_name, fname, nargs):
            k, s = defining(type_name, fname)
            if k is None:
                if script_key(type_name, nk) in master_keys and lib.get(script_key(type_name, nk)):
                    missing.add(f"{owner} calls {type_name}.{fname}(), which no master script defines now")
                return
            origin, stored, _ = lib.where[k]
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
        quests = _stage_calls(lib, attached, shown_name, nk, master_of)
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


def _stage_calls(lib, attached, shown_name, nk, master_of):
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
        for sig, fid, is_master, props in attached[sname]:
            for by, q, st in sorted(pairs, key=repr):
                if q[0] == "self":
                    qfid = fid if is_master and sig == "QUST" else None
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
                if stage is None:
                    e["unknown"] = True
                elif 0 <= stage <= 65535:  # a negative number is a "no stage" marker that never reaches SetStage
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
