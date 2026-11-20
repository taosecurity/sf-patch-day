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

from . import log, pe

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
    """One DLL to judge: a label for the report, and a way to get its bytes."""

    def __init__(self, label, path, member=None):
        self.label, self.path, self.member = label, path, member


def collect(inputs):
    """(DLL items, {lowercase Address Library file name: where}, [problems]) from files, folders and zips."""
    items, al_files, problems = [], {}, []

    def from_zip(zpath, label_base):
        try:
            with zipfile.ZipFile(zpath) as z:
                for info in z.infolist():
                    base = info.filename.replace("\\", "/").rsplit("/", 1)[-1]
                    if AL_RE.match(base):
                        al_files.setdefault(base.lower(), f"{zpath} :: {info.filename}")
                    if base.lower().endswith(".dll") and not info.is_dir():
                        items.append(Item(f"{label_base} :: {info.filename}", zpath, info.filename))
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
                        items.append(Item(rel, full))
                    elif low.endswith(".zip"):
                        from_zip(full, rel)
        elif os.path.isfile(path):
            low = path.lower()
            if low.endswith(".zip"):
                from_zip(path, os.path.basename(path))
            elif low.endswith(".dll"):
                items.append(Item(os.path.basename(path), path))
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


# ---- the verdict -----------------------------------------------------------------------------------------------
def describe_flags(block):
    a, s = block["address"], block["structure"]
    how = []
    if a & pe.ADDR_LIB2:
        how.append("Address Library")
    if a & pe.ADDR_LIB:
        how.append("old Address Library format")
    if a & pe.ADDR_SIG:
        how.append("signature scans")
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


def verdict(block, target, al_present, sfse_version=None):
    """(verdict, reason) for one plugin's version block on game version `target` (major, minor, build).
    al_present: True/False whether the Address Library file for `target` was found. sfse_version: SFSE's version
    packed like the block's fields, or None when unknown."""
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
    return MAY_FAIL, "version independent by signature scans"


def judge(item, target, al_present, sfse_version):
    """A result dict for one DLL."""
    out = {"file": item.label}

    def read(data):
        block = pe.sfse_block(data, item.label)
        return block, pe.mentions_address_library(data)

    try:
        block, mentions = _with_bytes(item, read)
    # zipfile can also raise RuntimeError (an encrypted member), NotImplementedError (Deflate64 and other methods),
    # EOFError and zlib.error (cut-off data). Any of these makes this one file unreadable, not the whole run.
    except (pe.PEError, OSError, zipfile.BadZipFile, KeyError, ValueError, RuntimeError, NotImplementedError,
            EOFError, zlib.error) as e:
        out.update(verdict=UNREADABLE, reason=str(e), what_to_do=WHAT_TO_DO[UNREADABLE])
        log.info("dlls", f"{item.label}: unreadable: {e}")
        return out
    v, reason = verdict(block, target, al_present, sfse_version)
    out.update(verdict=v, reason=reason, what_to_do=WHAT_TO_DO[v])
    if block is not None:
        out.update(name=block["name"], author=block["author"],
                   plugin_version=pe.plugin_version_text(block["plugin_version"]),
                   compatible=[pe.version_text(c) for c in block["compatible"]],
                   sfse_required=pe.version_text(block["sfse_required"]),
                   address_flags=block["address"], structure_flags=block["structure"], how=describe_flags(block))
        if mentions and not block["address"] & (pe.ADDR_LIB | pe.ADDR_LIB2):
            out["hint"] = "its code names an Address Library file, though its version data doesn't say it uses one"
        log.info("dlls", f"{item.label}: {block['name']!r} address={block['address']} structure="
                         f"{block['structure']} compatible={out['compatible']} sfse>={out['sfse_required'] or '-'} "
                         f"-> {v}: {reason}")
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
    if base["sfse_found"] is False:
        worst = max(worst, 1)
    if game_pass and any(r["verdict"] not in (NOT_SFSE, UNREADABLE) for r in results):
        worst = max(worst, 2)  # SFSE doesn't run on Game Pass, so no SFSE plugin loads there
    if problems:
        worst = 3
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {"game_version": ".".join(map(str, target)), "game_folder": game, "game_pass": game_pass,
            "sfse": base, "address_library": {"file": al_name, "found": al_where}, "inputs": inputs,
            "problems": [{"path": p, "problem": m} for p, m in problems], "plugins": results, "counts": counts,
            "exit": worst}


ORDER = [LOCKED, NEEDS_SFSE, NEEDS_AL, MAY_FAIL, UNREADABLE, WORKS, NOT_SFSE]


def text_report(rep, how_version):
    lines = [f"Game version: {rep['game_version']} ({how_version})"]
    if rep["game_pass"]:
        lines.append("Game Pass install: SFSE doesn't support the Game Pass version of Starfield, so SFSE plugins "
                     "don't load there at all.")
    s = rep["sfse"]
    if s["sfse_found"] is None:
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
            lines.append(f"    why: {r['reason']}")
            if v not in (WORKS, NOT_SFSE):
                lines.append(f"    what to do: {r['what_to_do']}")
            if r.get("hint"):
                lines.append(f"    hint: {r['hint']}")
    lines.append("")
    c = rep["counts"]
    summary = ", ".join(f"{v.lower()}: {c[v]}" for v in ORDER if c.get(v)) or "no DLLs"
    word = {0: "everything checked loads", 1: "some plugins wait for an update or need testing",
            2: "some plugins are locked to other game versions", 3: "some files couldn't be read"}[rep["exit"]]
    if rep["game_pass"] and rep["exit"] == 2:
        word = "SFSE plugins don't load on the Game Pass version" + (
            ", and some are locked to other game versions too" if c.get(LOCKED) else "")
    lines.append(f"RESULT: {word} ({summary})")
    return lines
