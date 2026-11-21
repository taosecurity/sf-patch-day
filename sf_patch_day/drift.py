# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""drift: did a game or Creation update change what a mod relies on?

A mods file (JSON) lists, per master plugin (Starfield.esm, a DLC, a Creation or another mod), the records a mod
relies on by Editor ID, the quest stages its scripts set, and the master's script functions it calls by name.
`snapshot` writes a baseline of those facts; `check` compares the installed masters with the baseline.

The baseline holds only file sizes, hashes, FormIDs, stage numbers, condition counts and function names with
their argument counts. It never holds record contents or script code.
"""
import datetime
import hashlib
import json
import os
import struct

from . import VERSION, log
from .plugin import Plugin, PluginError, PluginReadError, check_copies, clear_cache, find_plugin, subrecords


class DriftError(Exception):
    """A file can't be read or the mods file is wrong (exit 3). The message names the file and the fix."""


# ---- the mods file ---------------------------------------------------------------------------------------------
def load_mods(path):
    try:
        with open(path, encoding="utf-8") as f:
            mods = json.load(f)
    except OSError as e:
        raise DriftError(f"can't read the mods file {path}: {e.strerror}. Fix: check the path.")
    except json.JSONDecodeError as e:
        raise DriftError(f"{path} isn't valid JSON (line {e.lineno}, column {e.colno}: {e.msg}). Fix: correct it; "
                         f"see examples/mods.example.json.")
    problems = validate_mods(mods)
    if problems:
        raise DriftError(f"{path} doesn't follow the mods file format:\n  " + "\n  ".join(problems) +
                         "\nFix: see the README section 'The mods file' and examples/mods.example.json.")
    for spec in mods["masters"].values():
        for r in spec.get("records", []):
            if "type" in r:
                r["type"] = r["type"].upper()  # record types are upper case in the file (QUST, not qust)
    return mods


def validate_mods(mods):
    p = []
    if isinstance(mods, dict) and mods.get("masters") == {}:  # e.g. from drift init on a plugin with no overrides
        return ['"masters" is empty, so there is nothing to watch: add at least one master with the records, quest '
                'stages or script functions your mod relies on']
    if not isinstance(mods, dict) or not isinstance(mods.get("masters"), dict) or not mods["masters"]:
        return ['the top level needs "masters": {"<plugin file>": {...}, ...} with at least one plugin']

    def twice(names):
        seen, dup = set(), []
        for n in names:
            k = n.replace("\\", "/").lower()
            (dup.append(n) if k in seen else seen.add(k))
        return dup
    for n in twice(mods["masters"]):
        p.append(f'"{n}" is listed twice (names ignore case): list each master once')
    for name, spec in mods["masters"].items():
        if not isinstance(spec, dict):
            continue
        recs = spec.get("records", [])
        if isinstance(recs, list):
            for n in twice([r["edid"] for r in recs if isinstance(r, dict) and isinstance(r.get("edid"), str)]):
                p.append(f'"{name}": record "{n}" is listed twice (Editor IDs ignore case)')
        if isinstance(spec.get("functions"), dict):
            for n in twice(list(spec["functions"])):
                p.append(f'"{name}": script "{n}" is listed twice (paths ignore case and slash direction)')
    for name, spec in mods["masters"].items():
        if not isinstance(spec, dict):
            p.append(f'"{name}": must be an object')
            continue
        if os.path.basename(name) != name or not name.lower().endswith((".esm", ".esp", ".esl")):
            p.append(f'"{name}": must be a plugin file name (.esm, .esp or .esl) with no folder')
        recs = spec.get("records", [])
        if not isinstance(recs, list):
            p.append(f'"{name}".records must be a list')
            recs = []
        for i, r in enumerate(recs):
            if not isinstance(r, dict) or not isinstance(r.get("edid"), str) or not r["edid"]:
                p.append(f'"{name}".records[{i}] needs "edid": "<Editor ID>"')
                continue
            st = r.get("stages", [])
            if not isinstance(st, list) or not all(isinstance(s, int) and 0 <= s <= 65535 for s in st):
                p.append(f'"{name}".records[{i}] ({r["edid"]}): "stages" must be a list of stage numbers')
            if "type" in r and not (isinstance(r["type"], str) and len(r["type"]) == 4):
                p.append(f'"{name}".records[{i}] ({r["edid"]}): "type" must be a 4-letter record type such as QUST')
            if "used_by" in r and not isinstance(r["used_by"], str):
                p.append(f'"{name}".records[{i}] ({r["edid"]}): "used_by" must be text')
        ub = spec.get("used_by", [])
        if not isinstance(ub, list) or not all(isinstance(u, str) for u in ub):
            p.append(f'"{name}".used_by must be a list of names, such as ["MyMod.esm"]')
        funcs = spec.get("functions", {})
        if funcs:
            if not isinstance(spec.get("ba2"), str):
                p.append(f'"{name}": "functions" needs "ba2": "<archive file name>" (the archive holding the scripts)')
            elif os.path.basename(spec["ba2"]) != spec["ba2"]:
                p.append(f'"{name}".ba2 must be a file name with no folder')
            if not isinstance(funcs, dict) or not all(
                    isinstance(k, str) and isinstance(v, list) and all(isinstance(n, str) for n in v)
                    for k, v in funcs.items()):
                p.append(f'"{name}".functions must map "scripts/<path>.pex" to a list of function names')
    return p


# ---- reading the facts ----------------------------------------------------------------------------------------
def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def record_facts(sig, fid, body, plugin):
    subs = subrecords(body)
    facts = {"type": sig, "formid": plugin.low(fid), "sha256": hashlib.sha256(body).hexdigest()}
    ctda = [d for s, d in subs if s == "CTDA"]
    if sig in ("CNDF", "SMQN"):
        facts["conditions"] = len(ctda)
        facts["conditions_sha256"] = hashlib.sha256(b"".join(ctda)).hexdigest()
    if sig == "QUST":
        facts["stages"] = sorted({struct.unpack_from("<H", d, 0)[0] for s, d in subs if s == "INDX" and len(d) >= 2})
    return facts


def pex_functions(listing):
    """{name: param count} for the functions of the empty state, from an sf-pex-tools listing."""
    funcs, state, current = {}, None, None
    for line in listing:
        if line.startswith("  state "):
            state, current = line.strip()[6:], None
        elif state == "''" and line.startswith("    function "):
            current = line.strip()[9:]
            funcs[current] = 0
        elif current and line.startswith("      param "):
            funcs[current] += 1
        elif not line.startswith("      "):
            current = None
    return funcs


def script_functions(tools, ba2_path, scripts):
    """{script: {function: param count} or None when the script isn't in the archive}."""
    ba2, pex = tools.ba2, tools.pex
    out = {}
    try:
        with ba2.Archive(ba2_path) as a:
            index = {e["key"]: e for e in a.entries}
            for script in scripts:
                key = ba2.name_key(script)
                e = index.get(key)
                if e is None:
                    out[script] = None
                    log.info("drift", f"{ba2_path}: {script} not in the archive")
                    continue
                if key in a.duplicates:
                    raise DriftError(f"{ba2_path}: {script} is stored more than once; can't tell which one the game uses")
                a.check_can_unpack([e])
                out[script] = pex_functions(pex.listing(a.read(e), script, ignore_debug=True))
                log.info("drift", f"{ba2_path}: {script}: {len(out[script])} function(s) in the empty state")
    except (ba2.BA2Error, pex.PexError, OSError) as e:
        raise DriftError(f"{ba2_path}: {e}")
    return out


def find_file(name, dirs, what):
    p = find_plugin(name, dirs)
    if not p:
        raise DriftError(f"{what} {name} wasn't found in: {'; '.join(dirs)}. Fix: give the game's Data folder with "
                         f"--data, or the mod manager folder that holds it with --plugin-dir.")
    return p


def take(mods, dirs, tools=None, tools_msg=""):
    """The baseline dict for the masters in the mods file, read from the first of `dirs` that holds each."""
    clear_cache()  # a fresh look at the folders, also for callers that don't go through the command line
    snap = {"tool": f"sf-patch-day {VERSION}", "taken": datetime.date.today().isoformat(), "masters": {}}
    for name, spec in mods["masters"].items():
        path = find_file(name, dirs, "Master")
        recs = spec.get("records", [])
        types = {r["type"] for r in recs if r.get("type")}
        only = types if recs and all(r.get("type") for r in recs) else None
        try:
            with Plugin(path, dirs) as plugin:
                st = os.stat(path)
                max_own, probe, found = plugin.scan([r["edid"] for r in recs], only)
                entry = {
                    "size": st.st_size,
                    "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="minutes"),
                    "sha256": file_sha256(path),
                    "max_own_id": f"{max_own & plugin.mask:06X}",
                    "probe_id": f"{probe & plugin.mask:06X}",
                    "records": {},
                }
                for r in recs:
                    hit = found.get(r["edid"].lower())
                    try:
                        entry["records"][r["edid"]] = record_facts(*hit, plugin) if hit else None
                    except PluginError as e:
                        raise PluginError(f"{path}: {r['edid']}: {e}")
        except PluginReadError as e:
            raise DriftError(f"{e}. Fix: close the game and the Creation Kit, and check you can read the file.")
        except PluginError as e:
            raise DriftError(f"{e}. Fix: the file is damaged; verify the game files in Steam or reinstall the mod "
                             f"it comes from.")
        except OSError as e:
            raise DriftError(f"{path}: {e.strerror or e}. Fix: close the game and the Creation Kit, and check you can "
                             f"read the file.")
        log.info("drift", f"{name}: {path}, {len(found)} of {len(recs)} records found")
        if spec.get("functions"):
            if tools is None:
                entry["functions"] = None
                entry["functions_skipped"] = tools_msg or "sf-pex-tools not found"
            else:
                ba2_path = find_file(spec["ba2"], dirs, "Archive")
                got = script_functions(tools, ba2_path, list(spec["functions"]))
                entry["functions"] = {}
                for s, names in spec["functions"].items():
                    if got[s] is None:
                        entry["functions"][s] = None
                        continue
                    # Papyrus names ignore case: match the mods file's spelling to the script's either way.
                    low = {k.lower(): v for k, v in got[s].items()}
                    entry["functions"][s] = {n: low[n.lower()] for n in names if n.lower() in low}
        snap["masters"][name] = entry
    return snap


# ---- comparing ---------------------------------------------------------------------------------------------------
ACTION, NOTE, SKIP, WARN, OK = "ACTION", "NOTE", "SKIP", "WARN", "OK"
RESNAPSHOT = "after you next rebuild your mod, take a new baseline with snapshot --force"


def _key(name):
    """How the game matches names: case ignored, either slash."""
    return name.replace("\\", "/").lower()


def _by_key(d):
    return {_key(k): v for k, v in (d or {}).items()}


def not_found(spec, entry):
    """Stages and functions in the mods file that the snapshot didn't find: likely typos, worth fixing before an
    update. (Records and scripts not found are already on the snapshot's summary line.)"""
    out = []
    for r in spec.get("records", []):
        facts = entry["records"].get(r["edid"])
        if facts is None:
            continue
        for s in r.get("stages", []):
            if s not in facts.get("stages", []):
                out.append(f"{r['edid']} stage {s}" + ("" if facts["type"] == "QUST" else " (only quests have stages)"))
    for script, names in (spec.get("functions") or {}).items():
        got = (entry.get("functions") or {}).get(script)
        if entry.get("functions") is None:
            break  # skipped: said already
        if got is None:
            continue
        out += [f"{script} function {n}()" for n in names if n not in got]
    return out


def compare(base, now, mods):
    """[(level, text)]. ACTION = something the mod uses changed (rebuild); NOTE = changed, not used; SKIP = a check
    that couldn't run; OK = unchanged. Names are matched without regard to case, as the game does, so fixing a
    name's case in the mods file after the snapshot doesn't hide a check."""
    lines = []
    bm = _by_key(base.get("masters", {}))
    for name, spec in mods["masters"].items():
        users = ", ".join(spec.get("used_by", [])) or mods.get("mod") or "your mod"
        b, n = bm.get(_key(name)), now["masters"][name]
        if b is None:
            lines.append((NOTE, f"{name}: not in the baseline (added to the mods file after the snapshot; {RESNAPSHOT})"))
            continue
        base_records = _by_key(b.get("records"))
        if n.get("functions_skipped"):
            lines.append((SKIP, f"{name}: function checks skipped: {n['functions_skipped']}"))
        same = b["sha256"] == n["sha256"]
        if same:
            lines.append((OK, f"{name}: unchanged since {base.get('taken', '?')} ({users})"))
        else:
            lines.append((NOTE, f"{name}: UPDATED (was {b['size']:,} bytes, {b['modified']}; now {n['size']:,} "
                                f"bytes, {n['modified']}); highest own FormID {b['max_own_id']} -> {n['max_own_id']}"))
        # Scripts live in the archive, which can change while the plugin doesn't: functions are always compared.
        for rule in ([] if same else spec.get("records", [])):
            edid = rule["edid"]
            was, cur = base_records.get(_key(edid)), n["records"].get(edid)
            who = rule.get("used_by", users)
            why = f": {rule['why']}" if rule.get("why") else ""
            if cur is None:
                lines.append((ACTION if was is not None else NOTE,
                              f"  {edid}: GONE ({who}{why})" if was is not None else
                              f"  {edid}: not found now or in the baseline (check the Editor ID)"))
                continue
            if was is None:
                lines.append((NOTE, f"  {edid}: present now, missing in the baseline"))
                continue
            if cur["formid"] != was["formid"] or cur["type"] != was["type"]:
                lines.append((ACTION, f"  {edid}: now {cur['type']} {cur['formid']} (was {was['type']} "
                                      f"{was['formid']}; {who})"))
            for stage in rule.get("stages", []):
                if stage in cur.get("stages", []):
                    continue
                if stage in was.get("stages", []):
                    lines.append((ACTION, f"  {edid}: stage {stage} is GONE ({who} sets it)"))
                else:
                    lines.append((NOTE, f"  {edid}: stage {stage} not found now or in the baseline (check the "
                                        f"number{'' if cur['type'] == 'QUST' else '; only quests have stages'})"))
            if cur["sha256"] == was["sha256"]:
                continue
            if rule.get("copied"):
                extra = ""
                if "conditions" in cur and "conditions" in was:
                    extra = f"; conditions {was['conditions']} -> {cur['conditions']}" + (
                        "" if cur["conditions_sha256"] != was["conditions_sha256"] else " (same conditions)")
                lines.append((ACTION, f"  {edid}: CHANGED, and {who} ships a copy of it: rebuild{extra}"))
            else:
                extra = ""
                if "stages" in cur and cur["stages"] != was.get("stages"):
                    added = sorted(set(cur["stages"]) - set(was.get("stages", [])))
                    removed = sorted(set(was.get("stages", [])) - set(cur["stages"]))
                    extra = f"; stages added {added or 'none'}, removed {removed or 'none'}"
                lines.append((NOTE, f"  {edid}: record changed ({who}: review){extra}"))
        cur_funcs = n.get("functions")
        if cur_funcs is None:
            continue  # skipped (reported above) or none asked for
        was_funcs = b.get("functions")
        if was_funcs is None and spec.get("functions"):
            lines.append((NOTE, f"  {name}: no function baseline (snapshot ran without sf-pex-tools); {RESNAPSHOT}, "
                                f"with sf-pex-tools installed"))
            continue
        was_funcs = _by_key(was_funcs)
        for script, names in (spec.get("functions") or {}).items():
            was_script = was_funcs.get(_key(script))
            was = {k.lower(): v for k, v in (was_script or {}).items()}
            cur = cur_funcs.get(script)
            if cur is None:
                if was_script is None:
                    lines.append((NOTE, f"  {script}: not in {spec['ba2']} now or in the baseline (check the path)"))
                else:
                    lines.append((ACTION, f"  {script}: script GONE from {spec['ba2']}"))
                continue
            for fname in names:
                old = was.get(fname.lower())
                if fname not in cur:
                    if old is not None:
                        lines.append((ACTION, f"  {script}: function {fname}() is GONE (called by name)"))
                    else:
                        lines.append((NOTE, f"  {script}: function {fname}() not found now or in the baseline (check "
                                            f"the name; inherited functions and functions inside states aren't "
                                            f"listed)"))
                elif old is not None and cur[fname] != old:
                    lines.append((ACTION, f"  {script}: {fname}() now takes {cur[fname]} arguments (was {old})"))
    return lines


def result(lines):
    """(exit code, RESULT line)."""
    levels = {lv for lv, _ in lines}
    if ACTION in levels:
        return 2, "RESULT: ACTION NEEDED: rebuild the mods named above (exit 2)"
    also = "; also see the WARN line about copies of a file" if WARN in levels else ""
    if SKIP in levels:
        return 1, f"RESULT: no rebuild found, but some checks were skipped (see SKIP above{also}; exit 1)"
    if NOTE in levels:
        return 1, ("RESULT: no rebuild needed, but see the NOTE lines above (a master changed in a way your mod "
                   f"doesn't use, or a name to check{also}; exit 1)")
    if WARN in levels:
        return 1, "RESULT: no change found, but see the WARN line above about copies of a file (exit 1)"
    return 0, "RESULT: no change (exit 0)"


# ---- init: a starting mods file from a mod's own plugin ----------------------------------------------------------
def init(mod_path, dirs, tools=None, tools_msg=""):
    """(mods dict, notes, summary) listing every master record the mod overrides, as copied records, and, when
    sf-pex-tools is given (tools), the master script functions the mod's scripts call and the master quest stages
    they set. summary: counts for the report: "records" overridden, "functions" called, "quests" added for their
    stages, "staged" master quests whose stages the scripts set (added or overridden), "scripts" of the mod's own
    read (None without sf-pex-tools)."""
    clear_cache()
    check_copies(mod_path)  # before reading it: a second copy may explain a failure
    try:
        with Plugin(mod_path, dirs) as p:
            overrides = p.overrides()
            unknown = list(p.unknown)
            header_masters = list(p.masters)
    except (OSError, PluginError) as e:
        raise DriftError(f"{e}. Fix: check the path to your mod's plugin.")
    mod = os.path.basename(mod_path)
    masters, no_edid, no_master = {}, {}, 0
    for master, sig, fid, edid in overrides:
        if master is None:
            no_master += 1
            continue
        if not edid:
            no_edid[sig] = no_edid.get(sig, 0) + 1
            continue
        spec = masters.setdefault(master, {"used_by": [mod], "records": []})
        spec["records"].append({"edid": edid, "type": sig, "copied": True, "why": f"{mod} overrides this {sig}"})
    notes = []
    if unknown:
        notes.append(f"masters not found, so FE/FD record numbers may be misread: {', '.join(unknown)} "
                     f"(give --data or --plugin-dir)")
    if no_edid:
        notes.append("overridden records with no Editor ID can't be watched by name: " +
                     ", ".join(f"{n} {s}" for s, n in sorted(no_edid.items())))
    if no_master:
        notes.append(f"{no_master} record(s) point at a master the plugin doesn't list (damaged or unusual)")
    summary = {"records": sum(len(s["records"]) for s in masters.values()), "functions": 0, "quests": 0,
               "staged": 0, "scripts": None}
    if tools is None:
        notes.append(f"scripts not read: {tools_msg or 'sf-pex-tools not found'}. With sf-pex-tools, init also "
                     f"lists the master script functions your scripts call and the master quest stages they set")
        if not masters:
            notes.append("the plugin overrides no master records with Editor IDs; add records your scripts use by "
                         "hand")
        about = (f"Made by sf-patch-day {VERSION} drift init from {mod}, without sf-pex-tools. Add quest stages your "
                 f"scripts set and master script functions they call by name; see the README.")
    else:
        _add_script_part(mod_path, dirs, tools, masters, notes, summary)
        masters = _in_load_order(masters, header_masters)
        if not masters:
            notes.append("found nothing to watch: the plugin overrides no master records with Editor IDs, and its "
                         "scripts call no master script functions and set no master quest stages")
        about = (f"Made by sf-patch-day {VERSION} drift init from {mod}: the master records it overrides, the master "
                 f"script functions its scripts call and the master quest stages they set. Add anything else it "
                 f"relies on by hand; see the README.")
    return {"mod": mod, "about": about, "masters": masters}, notes, summary


def _in_load_order(masters, header_masters):
    """The masters found from overrides first (as before), then the others in the plugin's master order."""
    order = {m.lower(): i for i, m in enumerate(header_masters)}
    old = [m for m, s in masters.items() if not s.get("_new")]
    new = sorted((m for m, s in masters.items() if s.get("_new")),
                 key=lambda m: (order.get(m.lower(), 1 << 20), m.lower()))
    out = {}
    for m in old + new:
        out[m] = masters[m]
        out[m].pop("_new", None)
    return out


def _add_script_part(mod_path, dirs, tools, masters, notes, summary):
    """Adds the script findings to `masters` (in place)."""
    from . import scripts
    mod = os.path.basename(mod_path)
    try:
        funcs, quests, snotes, stats = scripts.analyze(mod_path, dirs, tools)
        edids = scripts.quest_edids(quests, mod_path, dirs) if quests else {}
    except scripts.ScriptError as e:
        notes.append(f"scripts not read: {e}")
        return
    summary["scripts"] = stats["own"]
    notes += snotes

    def spec_for(master):
        if master not in masters:
            masters[master] = {"used_by": [mod], "records": [], "_new": True}
        return masters[master]

    no_edid = 0
    for (master, fid), q in sorted(quests.items(), key=lambda kv: (kv[0][0].lower(), str(edids.get(kv[0])), kv[0][1])):
        edid = edids.get((master, fid))
        if not edid:
            no_edid += 1
            log.info("drift", f"{master} quest {fid:08X} (in {mod}'s numbering): no Editor ID found")
            continue
        spec = spec_for(master)
        summary["staged"] += 1
        by = ", ".join(sorted(q["by"], key=str.lower))
        by = f"stages set by {'scripts' if len(q['by']) > 1 else 'script'} {by}"
        rec = next((r for r in spec["records"] if r["edid"].lower() == edid.lower()), None)
        if rec is None:
            rec = {"edid": edid, "type": "QUST"}
            spec["records"].append(rec)
            summary["quests"] += 1
            rec["why"] = by[0].upper() + by[1:]
        else:
            rec["why"] += f"; {by}"
        if q["stages"]:
            rec["stages"] = sorted(set(rec.get("stages", [])) | q["stages"])
        if q["unknown"]:
            rec["why"] += " (a stage number not known before the game runs isn't listed)"
    if no_edid:
        notes.append(f"{no_edid} master quest(s) the scripts set stages on have no Editor ID or weren't found in "
                     f"their master, so they can't be watched by name")
    for master in sorted(funcs, key=str.lower):
        spec = spec_for(master)
        spec["ba2"] = funcs[master]["ba2"]
        spec["functions"] = {s: sorted(f, key=str.lower)
                             for s, f in sorted(funcs[master]["scripts"].items(), key=lambda kv: kv[0].lower())}
        summary["functions"] += sum(len(v) for v in spec["functions"].values())
