# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""framework: which library an SFSE plugin DLL was built with, read from the file's bytes only.

Plugins are built either on CommonLibSF (a large C++ library for Starfield) or on SFSE's own plugin API alone
("plain SFSE"). Each leaves text in the DLL: CommonLibSF's source paths and the names of its RE:: classes, or SFSE's
own source paths. A PDB (debug symbols) beside the DLL holds much more of the same. This module counts that text.
It never loads or runs the DLL, and it says "can't tell" rather than guess: a stripped or packed DLL, or a plain-SFSE
plugin that compiled none of SFSE's source paths in, leaves no sign.
"""
import re

from . import pe

COMMONLIBSF, PLAIN_SFSE, CANT_TELL = "CommonLibSF", "plain SFSE", "can't tell"
KINDS = (COMMONLIBSF, PLAIN_SFSE, CANT_TELL)
MIN_RE_TYPES = 3      # fewer RE names than this could be chance
MAX_DISTINCT = 100000  # distinct-name sets stop growing here
SFSE_EXPORTS = (b"SFSEPlugin_Load", b"SFSEPlugin_Version", b"SFSEPlugin_Preload")

# Every pattern has a fixed upper length and no nested repeats, so a scan is linear in the file size.
_TAIL = rb"[\w.\\/+-]{1,200}"
CLSF_PATH = re.compile(rb"commonlibsf[\\/](?:src|include|lib)[\\/]" + _TAIL, re.I)
CL_SHARED = re.compile(rb"commonlib-shared", re.I)
SFSE_PATH = re.compile(rb"(?:[\\/]sfse_common[\\/]|[\\/]sfse[\\/]sfse[\\/])" + _TAIL, re.I)
RE_RTTI = re.compile(rb"\.\?A[VUW][A-Za-z0-9_@?$]{1,200}@RE[LX]?@@")  # MSVC type names in RE, REL or REX
RE_TEXT = re.compile(rb"\bRE[LX]?::[A-Za-z_][A-Za-z0-9_]{0,80}")       # the same names as a PDB spells them
AL_TEXT = re.compile(rb"address library", re.I)
AL_TEXT16 = re.compile(re.escape("address library".encode("utf-16-le")), re.I)


def _distinct(pattern, data, fold=False):
    seen = set()
    for m in pattern.finditer(data):
        seen.add(m.group(0).lower() if fold else m.group(0))
        if len(seen) >= MAX_DISTINCT:
            break
    return len(seen)


def scan(data, is_pdb=False):
    """The four framework counts for one file's bytes (a DLL, or with is_pdb its PDB)."""
    re_types = _distinct(RE_RTTI, data)
    if is_pdb:
        re_types = max(re_types, _distinct(RE_TEXT, data))
    return {"commonlibsf_paths": _distinct(CLSF_PATH, data, fold=True),
            "commonlib_shared": CL_SHARED.search(data) is not None,
            "re_types": re_types,
            "sfse_paths": _distinct(SFSE_PATH, data, fold=True)}


def exports(data, name="file"):
    """Which of SFSE's standard exports the DLL's export table names (evidence only: both frameworks have them)."""
    try:
        names = pe.PE(data, name).export_names()
    except pe.PEError:
        return []
    return [n.decode("ascii") for n in SFSE_EXPORTS if n in names]


def address_library(data, block):
    """(uses Address Library, [what showed it]). False means no sign of it, never proven not."""
    why = []
    if block is not None and block["address"] & (pe.ADDR_LIB | pe.ADDR_LIB2):
        why.append("version data")
    if pe.mentions_address_library(data):
        why.append("versionlib file name")
    if AL_TEXT.search(data) or AL_TEXT16.search(data):
        why.append("Address Library text")
    return bool(why), why


def _n(n, one, many):
    return f"{n:,} {one if n == 1 else many}"


def _piece(dll, pdb, one, many, has_pdb):
    """'3 X', or with a PDB '3 X in the DLL, 600 in its PDB' (only the nonzero parts); None when both are 0."""
    if not dll and not pdb:
        return None
    if not has_pdb:
        return _n(dll, one, many)
    if dll and pdb:
        return f"{_n(dll, one, many)} in the DLL, {pdb:,} in its PDB"
    return f"{_n(dll, one, many)} in the DLL" if dll else f"{_n(pdb, one, many)} in its PDB"


def decide(dll, pdb=None):
    """(framework, why) from the DLL's counts and, when there is one, its PDB's counts (added together)."""
    has_pdb = pdb is not None
    p = pdb or {"commonlibsf_paths": 0, "commonlib_shared": False, "re_types": 0, "sfse_paths": 0}
    paths = dll["commonlibsf_paths"] + p["commonlibsf_paths"]
    shared = dll["commonlib_shared"] or p["commonlib_shared"]
    re_types = dll["re_types"] + p["re_types"]
    sfse = dll["sfse_paths"] + p["sfse_paths"]
    paths_text = _piece(dll["commonlibsf_paths"], p["commonlibsf_paths"], "CommonLibSF source path",
                        "CommonLibSF source paths", has_pdb)
    re_text = _piece(dll["re_types"], p["re_types"], "RE type name", "RE type names", has_pdb)
    sfse_text = _piece(dll["sfse_paths"], p["sfse_paths"], "SFSE source path", "SFSE source paths", has_pdb)
    if paths or shared or re_types >= MIN_RE_TYPES:
        shared_text = None
        if shared:
            shared_text = "commonlib-shared" + (" (in its PDB)" if has_pdb and not dll["commonlib_shared"] else "")
        parts = [x for x in (paths_text, shared_text, re_text if re_types >= MIN_RE_TYPES else None, sfse_text) if x]
        return COMMONLIBSF, ", ".join(parts)
    low = f"{re_text}, fewer than {MIN_RE_TYPES}" if re_types else None
    if sfse:
        return PLAIN_SFSE, "; ".join(x for x in (sfse_text, "no CommonLibSF signs" if not low else
                                                 f"no other CommonLibSF signs ({low})") if x)
    if low:
        return CANT_TELL, f"{low}; no other CommonLibSF or SFSE source signs"
    return CANT_TELL, "no CommonLibSF or SFSE source signs"
