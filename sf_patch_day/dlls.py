# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""dlls: which SFSE plugins load on a game version, and what each one waits for.

Each SFSE plugin DLL carries a small data block (SFSEPlugin_Version) saying which game versions it supports and
how it finds the game's code. SFSE reads it at startup and refuses plugins that don't fit. This module applies the
same rule (sfse PluginManager.cpp) before you launch, and adds the base layer every plugin needs: SFSE itself for
the game version, and the Address Library file for that version.
"""
import mmap
import os
import re
import struct
import zipfile
import zlib

from . import framework, hints, log, pe, risk

MAX_ZIP_MEMBER = 512 * 1024 * 1024  # a DLL bigger than this inside a zip is skipped (damaged or not a plugin)

# Verdicts and the exit code each one adds to.
WORKS, NEEDS_AL, MAY_FAIL, NEEDS_SFSE, LOCKED, NOT_SFSE, UNREADABLE = (
    "WORKS", "NEEDS ADDRESS LIBRARY", "MAY FAIL", "NEEDS NEWER SFSE", "LOCKED", "NOT AN SFSE PLUGIN", "UNREADABLE")
EXIT_FOR = {WORKS: 0, NOT_SFSE: 0, NEEDS_AL: 1, MAY_FAIL: 1, NEEDS_SFSE: 1, LOCKED: 2, UNREADABLE: 3}
WHAT_TO_DO = {
    WORKS: "nothing to do",
    NEEDS_AL: "install the Address Library file for this game version when its author releases it",
    MAY_FAIL: "SFSE loads it; it works only if the code it searches for is unchanged. Test it, or check its page",
    NEEDS_SFSE: "update SFSE to the version this plugin asks for",
    LOCKED: "SFSE refuses it on this game version: turn it off until its author releases an update",
    NOT_SFSE: "not judged (no SFSE version data: an ASI plugin, a helper DLL or a proxy DLL)",
    UNREADABLE: "the file is damaged or not a Windows DLL",
}
AL_RE = re.compile(r"^versionlib-(\d+)-(\d+)-(\d+)-(\d+)\.bin$", re.I)
SFSE_RUNTIME_RE = re.compile(r"^sfse_(\d+)_(\d+)_(\d+)\.dll$", re.I)


def parse_game_version(text):
    """'1.16.244' or '1.16.244.0' -> (1, 16, 244); None when it isn't a version."""
    m = re.fullmatch(r"\s*(\d{1,3})\.(\d{1,3})\.(\d{1,4})(?:\.\d+)?\s*", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def al_file_name(ver):
    return f"versionlib-{ver[0]}-{ver[1]}-{ver[2]}-0.bin"


def sfse_runtime_name(ver):
    return f"sfse_{ver[0]}_{ver[1]}_{ver[2]}.dll"


# ---- finding the files ---------------------------------------------------------------------------------------
class Item:
    """One DLL to judge: a label for the report, and a way to get its bytes. pdb: the PDB beside it (a path on disk,
    or a member of the same zip), or None."""

    def __init__(self, label, path, member=None, pdb=None):
        self.label, self.path, self.member, self.pdb = label, path, member, pdb


def _pdb_beside(full, names_here=None):
    """<same stem>.pdb in the DLL's folder, or None. names_here: the folder's file names, when already listed."""
    folder, base = os.path.split(full)
    want = os.path.splitext(base)[0].lower() + ".pdb"
    if names_here is None:
        try:
            names_here = os.listdir(folder or ".")
        except OSError:
            return None
    for n in names_here:
        if n.lower() == want and os.path.isfile(os.path.join(folder, n)):
            return os.path.join(folder, n)
    return None


def collect(inputs):
    """(DLL items, {lowercase Address Library file name: where}, [problems]) from files, folders and zips."""
    items, al_files, problems = [], {}, []

    def from_zip(zpath, label_base):
        try:
            with zipfile.ZipFile(zpath) as z:
                infos = z.infolist()
                pdbs = {i.filename.replace("\\", "/").lower(): i.filename for i in infos
                        if i.filename.lower().endswith(".pdb") and not i.is_dir()}
                for info in infos:
                    base = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
                    if AL_RE.match(base):
                        al_files.setdefault(base.lower(), f"{zpath} :: {info.filename}")
                    if base.lower().endswith(".dll") and not info.is_dir():
                        pdb = pdbs.get(info.filename.replace("\\", "/")[:-4].lower() + ".pdb")
                        items.append(Item(f"{label_base} :: {info.filename}", zpath, info.filename, pdb))
            log.info("collect", f"read zip {zpath}")
        except (zipfile.BadZipFile, OSError, ValueError, struct.error, KeyError, RuntimeError, NotImplementedError,
                EOFError, zlib.error) as e:  # a zip whose table zipfile can't make sense of
            problems.append((zpath, f"not a readable zip ({e})"))

    for path in inputs:
        if os.path.isdir(path):
            log.info("collect", f"searching folder {path}")
            def unreadable(e):
                problems.append((e.filename or path, f"can't be read ({e.strerror or e})"))
            for root, dirs, files in os.walk(path, onerror=unreadable):
                dirs.sort()
                for f in sorted(files):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, path)
                    if AL_RE.match(f):
                        al_files.setdefault(f.lower(), root)
                    low = f.lower()
                    if low.endswith(".dll"):
                        items.append(Item(rel, full, pdb=_pdb_beside(full, files)))
                    elif low.endswith(".zip"):
                        from_zip(full, rel)
        elif os.path.isfile(path):
            low = path.lower()
            if low.endswith(".zip"):
                from_zip(path, os.path.basename(path))
            elif low.endswith(".dll"):
                items.append(Item(os.path.basename(path), path, pdb=_pdb_beside(path)))
            else:
                problems.append((path, "not a .dll, .zip or folder"))
        else:
            problems.append((path, "no such file or folder"))
    return items, al_files, problems


def _with_bytes(item, fn):
    """Calls fn(data) with the DLL's bytes (an mmap for files on disk)."""
    if item.member is None:
        if os.path.getsize(item.path) == 0:
            raise pe.PEError(f"{item.label}: empty file")
        with open(item.path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return fn(m)
    with zipfile.ZipFile(item.path) as z:
        info = z.getinfo(item.member)
        if info.file_size > MAX_ZIP_MEMBER:
            raise pe.PEError(f"{item.label}: {info.file_size // 1048576} MB, too big for a plugin DLL")
        return fn(z.read(info))


MAX_PDB_FILE = 1024 * 1024 * 1024  # a PDB bigger than this on disk is skipped (in a zip, MAX_ZIP_MEMBER applies)


def _pdb_counts(item):
    """(label, framework counts) for the item's PDB, or (None, None) when there is none or it can't be read."""
    if not item.pdb:
        return None, None
    label = item.pdb if item.member is None else f"{item.path} :: {item.pdb}"
    try:
        if item.member is None:
            size = os.path.getsize(item.pdb)
            if size == 0 or size > MAX_PDB_FILE:
                log.info("framework", f"{label}: skipped ({size // 1048576} MB; the limit is 1024 MB)" if size
                         else f"{label}: skipped (empty)")
                return None, None
            with open(item.pdb, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                return label, framework.scan(m, is_pdb=True)
        with zipfile.ZipFile(item.path) as z:
            info = z.getinfo(item.pdb)
            if info.file_size == 0 or info.file_size > MAX_ZIP_MEMBER:
                log.info("framework", f"{label}: skipped ({info.file_size // 1048576} MB; the limit is 512 MB)"
                         if info.file_size else f"{label}: skipped (empty)")
                return None, None
            return label, framework.scan(z.read(info), is_pdb=True)
    except (OSError, zipfile.BadZipFile, KeyError, ValueError, RuntimeError, NotImplementedError, EOFError,
            zlib.error) as e:
        log.info("framework", f"{label}: can't be read, so it isn't used ({e})")
        return None, None


# ---- the verdict -----------------------------------------------------------------------------------------------
NO_SCAN_SIGNS = "says signature scans, but no pattern-scan signs found"
MAY_FAIL_NO_SIGNS = ("version independent by its version data's signature-scan claim, but no pattern-scan signs "
                     "were found (not proof: a scanner can keep its patterns as byte arrays), so it may use fixed "
                     "addresses and refuse to load or crash on this version")


def describe_flags(block, scan_signs=None):
    """How the plugin finds the game's code and which layout it promises. scan_signs: the signature-scan evidence
    (hints.signature_scan_evidence), [] when none was found, or None when it wasn't looked for."""
    a, s = block["address"], block["structure"]
    how = []
    if a & pe.ADDR_LIB2:
        how.append("Address Library")
    if a & pe.ADDR_LIB:
        how.append("old Address Library format")
    if a & pe.ADDR_SIG:
        how.append(NO_SCAN_SIGNS if scan_signs == [] else "signature scans")
    if not how:
        how.append("fixed addresses")
    lay = []
    if s & pe.STRUCT_NONE:
        lay.append("no game structures")
    if s & pe.STRUCT_1_14_70:
        lay.append("1.14.70+ structure layout")
    if not lay:
        lay.append("no structure promise")
    return ", ".join(how) + "; " + ", ".join(lay)


def verdict(block, target, al_present, sfse_version=None, scan_signs=None):
    """(verdict, reason) for one plugin's version block on game version `target` (major, minor, build).
    al_present: True/False whether the Address Library file for `target` was found. sfse_version: SFSE's version
    packed like the block's fields, or None when unknown. scan_signs (as in describe_flags) changes only the
    wording of a MAY FAIL reason, never the verdict: SFSE goes by the version data alone."""
    if block is None:
        return NOT_SFSE, "no SFSEPlugin_Version export"
    if block["data_version"] != 1:
        return LOCKED, f"version data format {block['data_version']} (SFSE knows only 1)"
    if sfse_version is not None and block["sfse_required"] > sfse_version:
        return NEEDS_SFSE, (f"asks for SFSE {pe.version_text(block['sfse_required'])}, "
                            f"installed SFSE is {pe.version_text(sfse_version)}")
    a, s = block["address"], block["structure"]
    independent = bool(a & (pe.ADDR_SIG | pe.ADDR_LIB2)) and bool(s & (pe.STRUCT_NONE | pe.STRUCT_1_14_70)) \
        and not block["reserved_breaking"]
    listed = pe.pack_version(*target) in block["compatible"]
    uses_al = bool(a & pe.ADDR_LIB2)
    if not independent and not listed:
        why = "lists only " + (", ".join(pe.version_text(v) for v in block["compatible"]) or "no versions")
        if a & pe.ADDR_LIB2 and not s & (pe.STRUCT_NONE | pe.STRUCT_1_14_70):
            why += " (it uses Address Library but makes no structure promise, so SFSE treats it as locked)"
        return LOCKED, why
    if uses_al and not al_present:
        return NEEDS_AL, f"uses Address Library; {al_file_name(target)} was not found"
    if listed:
        return WORKS, f"lists {pe.version_text(pe.pack_version(*target))}"
    if uses_al:
        return WORKS, "version independent; the Address Library file for this version is present"
    return MAY_FAIL, MAY_FAIL_NO_SIGNS if scan_signs == [] else "version independent by signature scans"


def judge(item, target, al_present, sfse_version):
    """A result dict for one DLL."""
    out = {"file": item.label}

    def read(data):
        block = pe.sfse_block(data, item.label)
        evidence = risk.read(data, item.label)  # every readable DLL: a bundled helper can be the one that matters
        if block is None:
            return block, pe.mentions_address_library(data), None, evidence, None, None
        counts = framework.scan(data)
        uses_al, al_why = framework.address_library(data, block)
        # The deeper looks share one pass over the type names. Hints are read when the DLL alone can't be placed
        # (a PDB can only add signs, so it can't make a placed DLL unplaced); they're kept only if the PDB doesn't
        # place it either.
        want_scan = bool(block["address"] & pe.ADDR_SIG)
        want_hints = framework.decide(counts)[0] == framework.CANT_TELL
        types = hints.type_names(data) if want_scan or want_hints else None
        scan_signs = hints.signature_scan_evidence(data, types) if want_scan else None
        found_hints = hints.framework_hints(data, types) if want_hints else None
        return (block, "versionlib file name" in al_why,
                (counts, framework.exports(data, item.label), uses_al, al_why), evidence, scan_signs, found_hints)

    try:
        block, mentions, fw, (imports, found), scan_signs, found_hints = _with_bytes(item, read)
    # zipfile can also raise RuntimeError (an encrypted member), NotImplementedError (Deflate64 and other methods),
    # EOFError and zlib.error (cut-off data). Any of these makes this one file unreadable, not the whole run.
    except (pe.PEError, OSError, zipfile.BadZipFile, KeyError, ValueError, RuntimeError, NotImplementedError,
            EOFError, zlib.error) as e:
        out.update(verdict=UNREADABLE, reason=str(e), what_to_do=WHAT_TO_DO[UNREADABLE])
        log.info("dlls", f"{item.label}: unreadable: {e}")
        return out
    v, reason = verdict(block, target, al_present, sfse_version, scan_signs)
    out.update(verdict=v, reason=reason, what_to_do=WHAT_TO_DO[v], imports=imports, risk=found)
    if block is not None:
        out.update(name=block["name"], author=block["author"],
                   plugin_version=pe.plugin_version_text(block["plugin_version"]),
                   compatible=[pe.version_text(c) for c in block["compatible"]],
                   sfse_required=pe.version_text(block["sfse_required"]),
                   address_flags=block["address"], structure_flags=block["structure"],
                   how=describe_flags(block, scan_signs), signature_scan_evidence=scan_signs)
        if scan_signs is not None:
            log.info("hints", f"{item.label}: version data says signature scans; pattern-scan signs: "
                              f"{', '.join(scan_signs) or 'none'}")
        if mentions and not block["address"] & (pe.ADDR_LIB | pe.ADDR_LIB2):
            out["hint"] = "its code names an Address Library file, though its version data doesn't say it uses one"
        log.info("dlls", f"{item.label}: {block['name']!r} address={block['address']} structure="
                         f"{block['structure']} compatible={out['compatible']} sfse>={out['sfse_required'] or '-'} "
                         f"-> {v}: {reason}")
        counts, exported, uses_al, al_why = fw
        pdb_label, pdb = _pdb_counts(item)
        kind, why = framework.decide(counts, pdb)
        out.update(framework=kind, framework_why=why,
                   framework_evidence=dict(counts, exports=exported, pdb=pdb_label, pdb_counts=pdb),
                   uses_address_library=uses_al, address_library_evidence=al_why)
        log.info("framework", f"{item.label}: {counts} exports={exported} pdb={pdb_label} {pdb or ''} -> {kind} "
                              f"({why}); Address Library {al_why or 'no signs'}")
        if kind == framework.CANT_TELL and found_hints is not None:
            c = found_hints.pop("counts")
            out["framework_hints"] = found_hints
            log.info("hints", f"{item.label}: {c['type_names']} type names; libraries "
                              f"{found_hints['libraries'] or 'none'}; SFSE API types "
                              f"{found_hints['sfse_api_types'] or 'none'} ({c['other_sfse_types']} other SFSE "
                              f"type names); {c['reader_messages']} Address Library reader and "
                              f"{c['check_messages']} game version check messages")
    else:
        m = SFSE_RUNTIME_RE.match(item.label.replace("\\", "/").rsplit("/", 1)[-1])
        if m:
            out["reason"] = f"this is SFSE itself, built for game version {'.'.join(m.groups())}"
        log.info("dlls", f"{item.label}: no SFSEPlugin_Version export -> {v}")
    return out


# ---- the base layer --------------------------------------------------------------------------------------------
def read_file_version(path):
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        return pe.PE(m, path).file_version()


def base_layer(game, target):
    """{'sfse': ..., 'sfse_version': packed or None, 'notes': [...]} for the game folder."""
    out = {"sfse_file": sfse_runtime_name(target), "sfse_found": None, "sfse_version": None, "notes": []}
    if not game:
        out["notes"].append("SFSE not checked (no game folder)")
        return out
    p = os.path.join(game, out["sfse_file"])
    out["sfse_found"] = os.path.isfile(p)
    if out["sfse_found"]:
        try:
            v = read_file_version(p)
            if v:
                out["sfse_version"] = pe.pack_version(v[1], v[2], v[3])  # SFSE stamps 0.<major>.<minor>.<build>
        except (pe.PEError, OSError) as e:
            out["notes"].append(f"couldn't read SFSE's version from {p}: {e}")
    log.info("base", f"{p}: {'found' if out['sfse_found'] else 'missing'}, version "
                     f"{pe.version_text(out['sfse_version']) or 'unknown'}")
    return out


def game_version(game):
    """(major, minor, build) read from <game>\\Starfield.exe, or raises OSError / pe.PEError."""
    exe = os.path.join(game, "Starfield.exe")
    v = read_file_version(exe)
    if not v:
        raise pe.PEError(f"{exe}: no version resource")
    log.info("base", f"{exe}: file version {'.'.join(map(str, v))}")
    return v[:3]


def run(inputs, target, game, game_pass=False, al_dirs=()):
    """The full report as a dict, with 'exit'. al_dirs: more folders where only the Address Library file is
    looked for (their DLLs aren't judged)."""
    items, al_files, problems = collect(inputs)
    for d in al_dirs:
        try:
            for f in os.listdir(d):
                if AL_RE.match(f):
                    al_files.setdefault(f.lower(), d)
        except OSError as e:
            log.info("base", f"can't list {d}: {e}")
    al_name = al_file_name(target)
    al_where = al_files.get(al_name.lower())
    log.info("base", f"Address Library file {al_name}: {al_where or 'not found'} "
                     f"(searched {len(inputs)} place(s); {len(al_files)} versionlib file(s) seen)")
    base = base_layer(game, target)
    results = [judge(i, target, al_where is not None, base["sfse_version"]) for i in items]
    worst = max([EXIT_FOR[r["verdict"]] for r in results] + [0])
    if base["sfse_found"] is False and not game_pass:  # on Game Pass SFSE never comes; that's said separately
        worst = max(worst, 1)
    if game_pass and any(r["verdict"] not in (NOT_SFSE, UNREADABLE) for r in results):
        worst = max(worst, 2)  # SFSE doesn't run on Game Pass, so no SFSE plugin loads there
    if problems:
        worst = 3
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    frameworks = {k: sum(1 for r in results if r.get("framework") == k) for k in framework.KINDS}
    read = [r for r in results if "risk" in r]
    risk_counts = {k: sum(1 for r in read if k in risk.found_kinds(r["risk"])) for k in risk.KINDS}
    return {"frameworks": frameworks, "risk_counts": risk_counts, "risk_dlls_read": len(read),
            "game_version": ".".join(map(str, target)), "game_folder": game,
            "game_pass": game_pass,
            "sfse": base, "address_library": {"file": al_name, "found": al_where}, "inputs": inputs,
            "problems": [{"path": p, "problem": m} for p, m in problems], "plugins": results, "counts": counts,
            "exit": worst}


ORDER = [LOCKED, NEEDS_SFSE, NEEDS_AL, MAY_FAIL, UNREADABLE, WORKS, NOT_SFSE]


def text_report(rep, how_version):
    lines = [f"Game version: {rep['game_version']} ({how_version})"]
    s = rep["sfse"]
    if rep["game_pass"]:
        lines.append("SFSE: this is a Game Pass install, and SFSE doesn't support Game Pass, so SFSE plugins don't "
                     "load here and no SFSE update will change that")
    elif s["sfse_found"] is None:
        lines.append("SFSE: not checked (no game folder; give --game to check it)")
    elif s["sfse_found"]:
        lines.append(f"SFSE: {pe.version_text(s['sfse_version']) or 'version unknown'} for this game version found "
                     f"({s['sfse_file']})")
    else:
        lines.append(f"SFSE: NOT FOUND for this game version ({s['sfse_file']} is missing). Every SFSE plugin waits "
                     f"for an SFSE update from its authors.")
    for n in s["notes"]:
        lines.append(f"  note: {n}")
    al = rep["address_library"]
    lines.append(f"Address Library: {al['file']} " + (f"found ({al['found']})" if al["found"] else
                 "NOT FOUND in the folders checked (plugins that use it wait for its update)"))
    for p in rep["problems"]:
        lines.append(f"CANNOT READ: {p['path']}: {p['problem']}")
    lines.append("")
    if not rep["plugins"]:
        lines.append("No DLLs found in: " + ", ".join(rep["inputs"]))
    for v in ORDER:
        for r in (r for r in rep["plugins"] if r["verdict"] == v):
            lines.append(f"{v:<22} {r['file']}")
            if "name" in r:
                lines.append(f"    {r['name']!r} by {r['author'] or 'unknown'}, plugin version {r['plugin_version']}; "
                             f"{r['how']}")
            if "framework" in r:
                al = (f"yes ({', '.join(r['address_library_evidence'])})" if r["uses_address_library"]
                      else "no signs")
                lines.append(f"    framework: {r['framework']} ({r['framework_why']}); Address Library: {al}")
            if "framework_hints" in r:
                lines.append(hints.hints_line(r["framework_hints"]))
            if "risk" in r:
                lines.append(risk.text_line(r["risk"], r["imports"]["problem"]))
            lines.append(f"    why: {r['reason']}")
            if v not in (WORKS, NOT_SFSE):
                lines.append(f"    what to do: {r['what_to_do']}")
            if r.get("hint"):
                lines.append(f"    hint: {r['hint']}")
    lines.append("")
    fw = rep["frameworks"]
    if any(fw.values()):
        lines.append("Frameworks: " + ", ".join(f"{k} {fw[k]}" for k in framework.KINDS))
    if rep["risk_dlls_read"]:
        lines.append(risk.summary_line(rep["risk_counts"], rep["risk_dlls_read"],
                                       sum(1 for r in rep["plugins"] if r.get("imports", {}).get("problem"))))
    c = rep["counts"]
    summary = ", ".join(f"{v.lower()}: {c[v]}" for v in ORDER if c.get(v)) or "no DLLs"
    word = {0: "everything checked loads", 1: "some plugins wait for an update or need testing",
            2: "some plugins are locked to other game versions", 3: "some files couldn't be read"}[rep["exit"]]
    if rep["game_pass"] and rep["exit"] == 2:
        word = "SFSE plugins don't load on the Game Pass version" + (
            ", and some are locked to other game versions too" if c.get(LOCKED) else "")
    lines.append(f"RESULT: {word} ({summary})")
    return lines
