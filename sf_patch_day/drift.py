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
from .plugin import Plugin, PluginError, find_plugin, subrecords


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
    if not isinstance(mods, dict) or not isinstance(mods.get("masters"), dict) or not mods["masters"]:
        return ['the top level needs "masters": {"<plugin file>": {...}, ...} with at least one plugin']
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
        except PluginError as e:
            raise DriftError(f"{e}. Fix: if the file is damaged, verify the game files in Steam or reinstall the mod.")
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
ACTION, NOTE, SKIP, OK = "ACTION", "NOTE", "SKIP", "OK"


def compare(base, now, mods):
    """[(level, text)]. ACTION = something the mod uses changed (rebuild); NOTE = changed, not used; SKIP = a check
    that couldn't run; OK = unchanged."""
    lines = []
    bm = base.get("masters", {})
    for name, spec in mods["masters"].items():
        users = ", ".join(spec.get("used_by", [])) or mods.get("mod") or "your mod"
        b, n = bm.get(name), now["masters"][name]
        if b is None:
            lines.append((NOTE, f"{name}: not in the baseline (run snapshot)"))
            continue
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
            was, cur = b["records"].get(edid), n["records"].get(edid)
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
            lines.append((NOTE, f"  {name}: no function baseline (snapshot ran without sf-pex-tools); run snapshot "
                                f"again to check functions next time"))
            continue
        for script, names in (spec.get("functions") or {}).items():
            was_script = (was_funcs or {}).get(script)
            was = was_script or {}
            cur = cur_funcs.get(script)
            if cur is None:
                if was_script is None:
                    lines.append((NOTE, f"  {script}: not in {spec['ba2']} now or in the baseline (check the path)"))
                else:
                    lines.append((ACTION, f"  {script}: script GONE from {spec['ba2']}"))
                continue
            for fname in names:
                if fname not in cur:
                    if fname in was:
                        lines.append((ACTION, f"  {script}: function {fname}() is GONE (called by name)"))
                    else:
                        lines.append((NOTE, f"  {script}: function {fname}() not found now or in the baseline (check "
                                            f"the name; inherited functions and functions inside states aren't "
                                            f"listed)"))
                elif fname in was and cur[fname] != was[fname]:
                    lines.append((ACTION, f"  {script}: {fname}() now takes {cur[fname]} arguments (was {was[fname]})"))
    return lines


def result(lines):
    """(exit code, RESULT line)."""
    levels = {lv for lv, _ in lines}
    if ACTION in levels:
        return 2, "RESULT: ACTION NEEDED: rebuild the mods named above (exit 2)"
    if SKIP in levels:
        return 1, "RESULT: no rebuild found, but some checks were skipped (see SKIP above; exit 1)"
    if NOTE in levels:
        return 1, "RESULT: a master changed, but nothing your mod uses (no rebuild; worth a look; exit 1)"
    return 0, "RESULT: no change (exit 0)"


# ---- init: a starting mods file from a mod's own plugin ----------------------------------------------------------
def init(mod_path, dirs):
    """(mods dict, notes) listing every master record the mod overrides, as copied records."""
    try:
        with Plugin(mod_path, dirs) as p:
            overrides = p.overrides()
            unknown = list(p.unknown)
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
    if not masters:
        notes.append("the plugin overrides no master records with Editor IDs; add records your scripts use by hand")
    return {"mod": mod, "about": f"Made by sf-patch-day {VERSION} drift init from {mod}. Add quest stages your "
                                 f"scripts set and master script functions they call by name; see the README.",
            "masters": masters}, notes
