# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""hints: two deeper looks at a plugin DLL's bytes, both evidence only (never a verdict or an exit code).

1. Signature-scan evidence. A plugin's version data can say it finds the game's code by signature scans (flag 1).
   That is the author's claim, so when the flag is set this module looks for signs of a pattern scanner in the
   DLL: pattern text such as "48 8B ?? ?? E8", scanner words such as "FindPattern", and type names holding
   Pattern, Scanner or SigScan. Without any, the report says the claim is unbacked.
2. Framework hints, for DLLs the framework module can't place: the libraries its type names come from, SFSE's
   plugin API types, and its own Address Library reader and game version check messages (quoted, escaped, cut).

Only names from the fixed tables below are printed, except the quoted messages, which are escaped and cut. Every
pattern has a fixed upper length and no nested repeats, so each scan is linear in the file size.
"""
import re

MAX_ITEMS = 2     # quotes per kind of message
QUOTE_CUT = 80    # characters kept of each quoted message
MAX_SEEN = 10000  # stop counting matches of one kind here

# ---- 1. signature-scan evidence ---------------------------------------------------------------------------------
_TOKEN = rb"(?:[0-9A-Fa-f]{2}|\?\??)"
PATTERN_TEXT = re.compile(rb"(?<=\0)" + _TOKEN + rb"(?: " + _TOKEN + rb"){5,300}(?=\0)")
HEX_LETTER = re.compile(rb"[A-Fa-f]")
SCANNER_WORDS = ("findpattern", "find_pattern", "patternscan", "pattern_scan", "pattern scan", "scanpattern",
                 "scan_pattern", "sigscan", "sig_scan", "signature scan", "aob scan", "aobscan",
                 "pattern not found", "signature not found", "sig found", "sig not found", "resolve signature")
SCANNER_TEXT = re.compile(b"|".join(re.escape(w.encode("ascii")) for w in SCANNER_WORDS), re.I)
RTTI = re.compile(rb"\.\?A[VUW][A-Za-z0-9_@?$]{1,400}")  # an MSVC type name (the part after .?AV, .?AU or .?AW)
# Case matters: spdlog's pattern_formatter is not a scanner. A bare "Scanner" is not enough either: Starfield has
# a hand scanner, so a mod's own ScannerMenu type is about the game, not about memory.
SCANNER_TYPE = re.compile(rb"Pattern|SigScan|Sig_Scan|(?:Memory|Mem|Aob|AOB|Byte|Sig|Signature)Scanner")


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def pattern_strings(data):
    """How many NUL-bounded pattern strings the bytes hold: 6 or more tokens, each two hex digits or ?/??, with at
    least one wildcard or at least two tokens holding a letter A-F (a table of digit-only numbers is not one)."""
    n = 0
    for m in PATTERN_TEXT.finditer(data):
        tokens = m.group(0).split(b" ")
        if any(t.startswith(b"?") for t in tokens) or sum(1 for t in tokens if HEX_LETTER.search(t)) >= 2:
            n += 1
            if n >= MAX_SEEN:
                break
    return n


def scanner_words(data):
    """The scanner words (from our table, lowercased) the bytes hold, in table order."""
    seen = set()
    for m in SCANNER_TEXT.finditer(data):
        seen.add(m.group(0).lower().decode("ascii"))
        if len(seen) == len(SCANNER_WORDS):
            break
    return [w for w in SCANNER_WORDS if w in seen]


def type_names(data):
    """The distinct MSVC type names in the bytes (bytes after the .?AV/.?AU/.?AW prefix), up to MAX_SEEN."""
    seen = set()
    for m in RTTI.finditer(data):
        seen.add(m.group(0)[4:])
        if len(seen) >= MAX_SEEN:
            break
    return seen


def signature_scan_evidence(data, types=None):
    """Our own descriptions of the pattern-scanner signs in the bytes; [] when there are none."""
    types = type_names(data) if types is None else types
    out = []
    n = pattern_strings(data)
    if n:
        out.append(_plural(n, "pattern string", "pattern strings"))
    words = scanner_words(data)
    if words:
        out.append("scanner text: " + ", ".join(words))
    t = sum(1 for name in types if SCANNER_TYPE.search(name))
    if t:
        out.append(_plural(t, "Pattern/Scanner type name", "Pattern/Scanner type names"))
    return out


# ---- 2. framework hints for "can't tell" DLLs ---------------------------------------------------------------------
LIBRARIES = ("spdlog", "fmt", "nlohmann", "toml", "boost", "Xbyak", "DKUtil", "YAML", "glm", "cereal")
LIBRARY_NOTE = "CommonLibSF plugins use spdlog and fmt, but so do others"
SFSE_API_TYPES = ("SFSEInterface", "SFSEMessagingInterface", "SFSETrampolineInterface", "SFSETaskInterface",
                  "SFSEMenuInterface")  # the interfaces in SFSE's PluginAPI.h
_SFSE_TYPE = re.compile(rb"(?:^|@)(SFSE[A-Za-z]{0,40}Interface)(?=@)")
ASCII_TEXT = re.compile(rb"(?<=\0)[\x01-\x7f]{8,400}(?=\0)")  # a NUL-bounded ASCII string
READER_WORDS = re.compile(r"address library|addresslib|versionlib", re.I)
CHECK_WORDS = re.compile(r"game version|runtime version|unsupported version|version mismatch|wrong version|"
                         r"supported version", re.I)
NONE_LINE = "    framework hints: none (a stripped or packed DLL leaves none)"


def quote(text, at=0):
    """A message from the file, safe to show: QUOTE_CUT characters of it (starting a little before `at`, where the
    word that picked it is, when that word would be cut off), then every character outside printable ASCII (and the
    double quote and the backslash, so the file's own text can't look like this escaping) shown as \\xNN. '...' marks
    each cut end."""
    start = max(0, at - 20) if at > QUOTE_CUT - 20 else 0
    cut = text[start:start + QUOTE_CUT]
    shown = re.sub(r'[^\x20-\x7e]|["\\]', lambda m: f"\\x{ord(m.group(0)):02x}", cut)
    return ("..." if start else "") + shown + ("..." if len(text) > start + QUOTE_CUT else "")


def messages(data):
    """(reader quotes, version check quotes, reader count, check count). A message with both kinds of words is a
    reader message."""
    reader, check, counts = [], [], [0, 0]
    for m in ASCII_TEXT.finditer(data):
        text = m.group(0).decode("ascii")
        word = READER_WORDS.search(text)
        which = 0
        if not word:
            word, which = CHECK_WORDS.search(text), 1
        if not word:
            continue
        counts[which] += 1
        keep = (reader, check)[which]
        q = quote(text, word.start())
        if len(keep) < MAX_ITEMS and q not in keep:
            keep.append(q)
        if sum(counts) >= MAX_SEEN:
            break
    return reader, check, counts[0], counts[1]


def framework_hints(data, types=None):
    """The JSON 'framework_hints' part, plus 'counts' for the log (the caller removes it)."""
    types = type_names(data) if types is None else types
    libs, api, unknown_api = set(), set(), 0
    for name in types:
        parts = set(name.split(b"@")[1:])  # the namespaces and outer classes (the first part is the type itself)
        libs.update(lib for lib in LIBRARIES if lib.encode("ascii") in parts)
        for m in _SFSE_TYPE.finditer(name):
            found = m.group(1).decode("ascii")
            if found in SFSE_API_TYPES:
                api.add(found)
            else:
                unknown_api += 1
    reader, check, n_reader, n_check = messages(data)
    return {"libraries": [lib for lib in LIBRARIES if lib in libs],
            "sfse_api_types": [t for t in SFSE_API_TYPES if t in api],
            "address_library_text": reader, "version_check_text": check,
            "counts": {"type_names": len(types), "other_sfse_types": unknown_api, "reader_messages": n_reader,
                       "check_messages": n_check}}


def hints_line(h):
    """The 'framework hints' line under a "can't tell" DLL in the text report."""
    parts = []
    if h["libraries"]:
        note = f" ({LIBRARY_NOTE})" if {"spdlog", "fmt"} & set(h["libraries"]) else ""
        parts.append("libraries " + ", ".join(h["libraries"]) + note)
    if h["sfse_api_types"]:
        parts.append("SFSE plugin API types (" + ", ".join(h["sfse_api_types"]) + ")")
    if h["address_library_text"]:
        parts.append("its own Address Library reader text: " + ", ".join(f'"{q}"' for q in h["address_library_text"]))
    if h["version_check_text"]:
        parts.append("its own game version check text: " + ", ".join(f'"{q}"' for q in h["version_check_text"]))
    return "    framework hints: " + "; ".join(parts) if parts else NONE_LINE
