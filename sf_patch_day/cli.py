# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""sf-patch-day command line. Run with --help, or see the README."""
import argparse
import json
import os
import sys
import traceback

from . import VERSION, creations, dlls, drift, log, paths, pe, pextools
from . import plugin as plugin_module
from .plugin import Plugin, PluginError, PROBE_TYPES

CANNOT = 3


class Parser(argparse.ArgumentParser):
    """Usage mistakes exit 3 ("can't check"), so exit 2 always means "rebuild" or "locked"."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"RESULT: CANNOT CHECK: {message}. Fix: see {self.prog} --help", file=sys.stderr)
        sys.exit(CANNOT)


def common(p):
    p.add_argument("--verbose", action="store_true", help="write the troubleshooting log to the screen (stderr)")
    p.add_argument("--log", metavar="FILE", help="write the troubleshooting log to FILE")


def where(p):
    p.add_argument("--data", metavar="FOLDER", help="the game's Data folder (default: found automatically)")
    p.add_argument("--plugin-dir", metavar="FOLDER", action="append", default=[],
                   help="a folder searched before Data for plugins and archives (a mod manager's mod folder); "
                        "may be given more than once")


def build_parser():
    ap = Parser(prog="sf-patch-day", description=(
        "After a Starfield update: which SFSE plugins still load (dlls), and did the update change what your mod "
        "relies on (drift), and what a Creations update changed (creations). Read-only on the game folder. Options go after the command name."))
    ap.add_argument("--version", action="version", version=f"sf-patch-day {VERSION}")
    sub = ap.add_subparsers(dest="cmd", metavar="command", parser_class=Parser)

    d = sub.add_parser("dlls", help="which SFSE plugin DLLs load on this game version, and which framework each "
                                    "was built with", description=(
        "Which SFSE plugin DLLs load on this game version, and what each waits for. Each SFSE plugin also gets a "
        "framework line: CommonLibSF, plain SFSE or can't tell, from text left in the DLL (and a same-name .pdb "
        "beside it), with the evidence, and whether it shows signs of using Address Library. A stripped or packed "
        "DLL gives can't tell. The framework never changes the exit code. DLLs are read, never loaded or run."))
    d.add_argument("paths", nargs="*", metavar="PATH",
                   help="DLLs, zips or folders to check (default: the game's Data\\SFSE\\Plugins); "
                        "one .dll checks just that plugin")
    d.add_argument("--game", metavar="FOLDER", help="the game folder holding Starfield.exe (default: found automatically)")
    d.add_argument("--game-version", metavar="X.Y.Z", help="judge against this game version instead of the "
                                                           "installed Starfield.exe's (for example 1.16.244)")
    d.add_argument("--json", action="store_true", help="print the report as JSON")
    common(d)

    dr = sub.add_parser("drift", help="did an update change the records, stages or functions your mod relies on")
    dsub = dr.add_subparsers(dest="drift_cmd", metavar="step", parser_class=Parser)
    di = dsub.add_parser("init", help="write a starting mods file from your mod's plugin")
    di.add_argument("plugin", help="your mod's plugin (.esm/.esp/.esl)")
    di.add_argument("-o", "--out", required=True, metavar="FILE", help="the mods file to write")
    di.add_argument("--force", action="store_true", help="overwrite FILE if it exists")
    di.add_argument("--pex-tools", metavar="FOLDER", help="the sf-pex-tools folder (needed to read your mod's "
                                                         "scripts)")
    where(di)
    common(di)
    for name, helptext in (("snapshot", "write a baseline from the installed masters"),
                           ("check", "compare the installed masters with the baseline")):
        x = dsub.add_parser(name, help=helptext)
        x.add_argument("--mods", required=True, metavar="FILE", help="the mods file (what your mod relies on)")
        if name == "snapshot":
            x.add_argument("-o", "--out", required=True, metavar="FILE", help="the baseline file to write")
            x.add_argument("--force", action="store_true", help="overwrite FILE if it exists (take a new baseline "
                                                                "only after rebuilding your mod)")
        else:
            x.add_argument("--baseline", required=True, metavar="FILE", help="the baseline written by snapshot")
            x.add_argument("--json", action="store_true", help="print the findings as JSON")
        x.add_argument("--pex-tools", metavar="FOLDER", help="the sf-pex-tools folder (needed for function checks)")
        where(x)
        common(x)

    c = sub.add_parser("creations", help="what a Creations update changed: Creations added, removed or updated "
                                         "since the saved copy of the game's ContentCatalog.txt", description=(
        "Compares the game's Creations catalog (ContentCatalog.txt) with a copy saved on an earlier run and lists "
        "the Creations added, removed or updated (version, title, files, size, achievement-friendly). The first "
        "run saves a copy and reports nothing. Later runs leave the saved copy alone unless you add --save. The "
        "game's Timestamp field is not compared, because the game rewrites it when a save loads. The game's file "
        "is only read. Exit 0 no changes (or a first copy saved), 1 changes, 3 can't check."))
    c.add_argument("--catalog", metavar="FILE", help="the game's ContentCatalog.txt (default: "
                                                     "%%LOCALAPPDATA%%\\Starfield\\ContentCatalog.txt, for Steam and "
                                                     "Game Pass; on Linux, the Proton prefix of each Steam library)")
    c.add_argument("--saved", metavar="FILE", help="the saved earlier copy (default: "
                                                   "%%LOCALAPPDATA%%\\sf-patch-day\\ContentCatalog-saved.txt; on "
                                                   "Linux, $XDG_STATE_HOME/sf-patch-day)")
    c.add_argument("--save", action="store_true", help="after the report, make the current catalog the new saved "
                                                       "copy")
    c.add_argument("--json", action="store_true", help="print the report as JSON")
    common(c)

    f = sub.add_parser("fingerprint", help="a plugin's probe FormID and highest own FormID (for in-game checks)")
    f.add_argument("plugin", help="the plugin file, or a name looked up in --data and --plugin-dir")
    where(f)
    common(f)
    return ap


def say(line=""):
    """Prints, replacing characters the console can't show."""
    enc = sys.stdout.encoding or "utf-8"
    print(str(line).encode(enc, "replace").decode(enc, "replace"))


def fail(msg):
    # A case-copy warning found before the failure may explain it. Shown with --json too: a run that stops here
    # never prints its JSON report, so its output is plain text anyway.
    say_warnings(always=True)
    say(f"RESULT: CANNOT CHECK: {msg}")
    log.info("error", msg)
    return CANNOT


def inside(path, folder):
    try:
        p, f = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(folder))
        return os.path.commonpath([p, f]) == f
    except ValueError:  # different drives
        return False


def same_folder(path, other):
    """True when path is other or sits right beside it (the same folder; subfolders don't count)."""
    a = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(path))))
    b = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(other))))
    return a == b


def data_dirs(args):
    """The folders to search for masters and archives: --plugin-dir ones first, then Data. (dirs, Data, game)."""
    data, game = args.data, None
    if not data:
        game, _ = paths.find_game(None)
        data = paths.data_folder(game) if game else None
    if data and not os.path.isdir(data):
        raise drift.DriftError(f"--data {data}: no such folder. Fix: give the game's Data folder.")
    dirs = list(args.plugin_dir) + ([data] if data else [])
    for d in args.plugin_dir:
        if not os.path.isdir(d):
            raise drift.DriftError(f"--plugin-dir {d}: no such folder.")
    if not dirs:
        raise drift.DriftError("the game's Data folder wasn't found. Fix: give it with --data <folder> (for a "
                               "Steam install, <Steam>\\steamapps\\common\\Starfield\\Data).")
    log.info("paths", f"plugin search order: {dirs}")
    return dirs, data


def refuse_game_folder(out, data):
    """Refuses writing into the Data folder, or the game folder above it when that holds Starfield.exe."""
    if not data:
        return
    guard = os.path.dirname(os.path.normpath(data))
    if not os.path.isfile(os.path.join(guard, "Starfield.exe")):
        guard = data
    if inside(out, guard):
        raise drift.DriftError(f"{out} is inside the game folder. sf-patch-day never writes there. Fix: write it to "
                               f"your own folder, next to your mod's source.")


def write_json(path, obj, force=True):
    if not force and os.path.exists(path):
        raise drift.DriftError(f"{path} already exists. Fix: add --force to overwrite it, or pick another name.")
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=1)
            f.write("\n")
    except OSError as e:
        raise drift.DriftError(f"can't write {path}: {e.strerror}. Fix: pick a folder you can write to.")


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise drift.DriftError(f"can't read the {what} {path}: {e.strerror}. Fix: check the path, or run snapshot first.")
    except json.JSONDecodeError as e:
        raise drift.DriftError(f"the {what} {path} isn't valid JSON (line {e.lineno}: {e.msg}). Fix: restore it from "
                               f"your backup or version control; a new snapshot only helps if your mod works with the "
                               f"masters as they are now.")


# ---- commands ---------------------------------------------------------------------------------------------------
def cmd_dlls(args):
    game = None
    if args.game or not args.paths or not args.game_version:
        game, _how = paths.find_game(args.game)
        if game is None and args.game:
            return fail(f"--game {args.game}: no such folder. Fix: give the folder that holds Starfield.exe.")
    if args.game_version:
        target = dlls.parse_game_version(args.game_version)
        if not target:
            return fail(f"--game-version {args.game_version!r} isn't a version. Fix: write it like 1.16.244.")
        how_version = "given with --game-version"
    elif game:
        try:
            target = dlls.game_version(game)
        except (OSError, pe.PEError) as e:
            return fail(f"couldn't read the game version from {os.path.join(game, 'Starfield.exe')} ({e}). Fix: give "
                        f"it with --game-version, for example --game-version 1.16.244.")
        how_version = f"read from {os.path.join(game, 'Starfield.exe')}"
    else:
        return fail("Starfield wasn't found, so the game version is unknown. Fix: give --game <folder holding "
                    "Starfield.exe> or --game-version X.Y.Z.")
    inputs, al_dirs = list(args.paths), []
    if not inputs:
        if not game:
            return fail("no DLLs given and the game wasn't found. Fix: give a folder, zip or DLL, or --game.")
        inputs = [paths.sfse_plugins_folder(game)]
    elif game:
        # The Address Library file usually lives in the game's plugin folder even when you check a download.
        al_dirs.append(paths.sfse_plugins_folder(game))
    log.info("dlls", f"target {target}, game {game}, inputs {inputs}, Address Library also looked for in {al_dirs}")
    rep = dlls.run(inputs, target, game, game_pass=bool(game and paths.is_game_pass(game)), al_dirs=al_dirs)
    if args.json:
        say(json.dumps(rep, indent=1))
    else:
        say(f"sf-patch-day {VERSION} dlls")
        for line in dlls.text_report(rep, how_version):
            say(line)
    return rep["exit"]


def cmd_drift(args):
    if not getattr(args, "drift_cmd", None):  # a bare "drift" (main() also stops it first): the help and RESULT
        return missing_step(args, drift_step=True)
    dirs, data = data_dirs(args)
    if args.drift_cmd == "init":
        refuse_game_folder(args.out, data)
        if os.path.exists(args.out) and not args.force:  # before reading the scripts
            raise drift.DriftError(f"{args.out} already exists. Fix: add --force to overwrite it, or pick another "
                                   f"name.")
        tools, tools_msg = pextools.find(args.pex_tools)
        if tools is None and args.pex_tools:
            return fail(tools_msg)
        mods, notes, summary = drift.init(args.plugin, dirs, tools, tools_msg)
        write_json(args.out, mods, force=args.force)
        scripts_read = tools is not None and summary["scripts"] is not None  # None: the script part failed
        if not scripts_read:
            say(f"wrote {args.out}: {summary['records']} overridden record(s) in {len(mods['masters'])} master(s)")
        else:
            say(f"wrote {args.out}: {summary['records']} overridden record(s), {summary['functions']} master script "
                f"function(s) your scripts call and {summary['staged']} master quest(s) they set stages on, in "
                f"{len(mods['masters'])} master(s)")
            say(f"  read {summary['scripts']} of your mod's own script(s) with {tools_msg}")
        for m, s in mods["masters"].items():
            staged = sum(1 for r in s["records"] if r.get("stages"))
            nf = sum(len(v) for v in s.get("functions", {}).values())
            say(f"  {m}: {len(s['records'])} record(s)" + (f", {staged} with quest stages" if staged else "")
                + (f", {nf} function(s) in {len(s['functions'])} script(s) from {s['ba2']}" if nf else ""))
        for note in notes:
            say(f"note: {note}")
        say_warnings()
        if mods["masters"] and tools is None:
            say("Next: add the quest stages your scripts set and the master script functions they call (or run init "
                "again with sf-pex-tools), then run drift snapshot.")
        elif mods["masters"] and not scripts_read:
            say("Next: add the quest stages your scripts set and the master script functions they call by hand (the "
                "\"scripts not read\" note says why init couldn't), then run drift snapshot.")
        elif mods["masters"]:
            say("Next: check the file, add anything else your mod relies on, then run drift snapshot "
                "(with sf-pex-tools, for the function checks).")
        else:  # an empty file: snapshot would refuse it, so say what it needs first
            say(f"Next: {args.out} has nothing to watch yet. Add at least one master with the records, quest stages "
                f"or script functions your mod relies on (README section 'The mods file', "
                f"examples/mods.example.json), then run drift snapshot.")
        return 0
    mods = drift.load_mods(args.mods)
    if args.drift_cmd == "snapshot":
        # Before the (slow) scan: refuse a target we won't write.
        refuse_game_folder(args.out, data)
        if os.path.exists(args.out) and not args.force:
            raise drift.DriftError(f"{args.out} already exists. Fix: add --force to replace it (only after you rebuild "
                                   f"your mod), or pick another name.")
    tools, tools_msg = (None, "no functions listed")
    if any(s.get("functions") for s in mods["masters"].values()):
        tools, tools_msg = pextools.find(args.pex_tools)
        if tools is None and args.pex_tools:
            return fail(tools_msg)
    now = drift.take(mods, dirs, tools, tools_msg)
    if args.drift_cmd == "snapshot":
        write_json(args.out, now, force=args.force)
        for name, e in now["masters"].items():
            missing = [k for k, v in e["records"].items() if v is None]
            gone = [s for s, v in (e.get("functions") or {}).items() if v is None]
            say(f"{name}: {len(e['records'])} record(s) ({len(missing)} not found"
                f"{': ' + ', '.join(missing) if missing else ''}), highest own FormID {e['max_own_id']}, probe "
                f"{e['probe_id']}"
                + (f", {sum(len(v or {}) for v in e['functions'].values())} function(s)" if e.get("functions") else "")
                + (f", scripts not found (check the path and the \"ba2\" archive name): {', '.join(gone)}"
                   if gone else "")
                + (f"; function checks skipped: {e['functions_skipped']}" if e.get("functions_skipped") else ""))
            for warning in drift.not_found(mods["masters"][name], e):
                say(f"  not found (check the name): {warning}")
        say_warnings()
        say(f"wrote {args.out}")
        return 0
    base = load_json(args.baseline, "baseline")
    if not isinstance(base, dict) or not isinstance(base.get("masters"), dict):
        return fail(f"{args.baseline} isn't an sf-patch-day baseline. Fix: run drift snapshot to make one.")
    lines = drift.compare(base, now, mods)
    # Several copies that differ only in case: the check may describe a file the game doesn't load.
    lines += [(drift.WARN, w) for w in plugin_module.warnings()]
    code, res = drift.result(lines)
    if args.json:
        say(json.dumps({"findings": [{"level": lv, "text": t.strip()} for lv, t in lines], "exit": code}, indent=1))
    else:
        for level, text in lines:
            say(f"{level:6} {text}")
        say(res)
    return code


def cmd_creations(args):
    if args.catalog:
        catalog, tried = args.catalog, [args.catalog]
    else:
        tried = paths.candidate_catalogs()
        catalog = next((p for p in tried if os.path.isfile(p)), None)
    log.info("creations", f"catalog places tried: {tried}; using {catalog}")
    if not catalog or not os.path.isfile(catalog):
        where_ = catalog or ", ".join(tried) or "(no place to look)"
        return fail(f"the Creations catalog wasn't found ({where_}). Fix: start the game once and open the Creations "
                    f"menu, or give --catalog <path to ContentCatalog.txt>.")
    saved = args.saved or paths.default_saved_catalog()
    log.info("creations", f"saved copy: {saved}" + ("" if args.saved else " (the default)"))
    if same_folder(saved, catalog):
        return fail(f"{'--saved' if args.saved else 'The saved copy'} {saved} is in the folder that holds the game's catalog. sf-patch-day never writes "
                    f"there. Fix: give --saved a file in your own folder, or leave it out for the default.")
    game, _ = paths.find_game(None)
    if game and inside(saved, game):
        return fail(f"--saved {saved} is inside the game folder. sf-patch-day never writes there. Fix: give --saved a "
                    f"file in your own folder, or leave it out for the default.")
    raw, header, now = creations.read(catalog, "Creations catalog", "start the game once and open the Creations "
                                      "menu so it writes the file again, or give --catalog the right file.")
    if os.path.isdir(saved):
        return fail(f"--saved {saved} is a folder. Fix: give --saved a file name, such as "
                    f"{os.path.join(saved, 'ContentCatalog-saved.txt')}.")
    head = f"Creations catalog: {catalog} ({len(now)} Creations)"
    if not os.path.exists(saved):
        creations.save_copy(raw, saved)
        if args.json:
            say(json.dumps({"catalog": catalog, "saved": saved, "saved_at": None, "first_copy_saved": True,
                            "saved_now": True, "catalog_version": None,
                            "counts": {"current": len(now), "saved": 0, "added": 0, "removed": 0, "updated": 0,
                                       "unchanged": 0, "timestamp_only": 0},
                            "added": [], "removed": [], "updated": [], "result": "first copy saved", "exit": 0},
                           indent=1))
        else:
            say(head)
            say(f"RESULT: SAVED a first copy of the catalog to {saved}. Run sf-patch-day creations again after the "
                f"next Creations or game update to see what changed.")
        return 0
    when = creations.saved_time(saved)
    _raw, old_header, old = creations.read(saved, "saved copy", "delete it, or give --saved another file, then run "
                                           "again to save a fresh copy.")
    rep = creations.compare(old, now)
    n_changes = len(rep["added"]) + len(rep["removed"]) + len(rep["updated"])
    code = 1 if n_changes else 0
    ov, nv = old_header.get("Version"), header.get("Version")
    if args.save:
        creations.save_copy(raw, saved)
    if args.json:
        say(json.dumps({"catalog": catalog, "saved": saved,
                        "saved_at": when.isoformat(timespec="seconds") if when else None,
                        "first_copy_saved": False, "saved_now": bool(args.save),
                        "catalog_version": None if ov == nv else {"old": ov, "new": nv},
                        "counts": {"current": len(now), "saved": len(old), "added": len(rep["added"]),
                                   "removed": len(rep["removed"]), "updated": len(rep["updated"]),
                                   "unchanged": rep["unchanged"], "timestamp_only": rep["timestamp_only"]},
                        "added": rep["added"], "removed": rep["removed"], "updated": rep["updated"],
                        "result": "changes" if n_changes else "no changes", "exit": code}, indent=1))
        return code
    say(head)
    say(f"Compared with: {saved} (saved {when.strftime('%Y-%m-%d %H:%M') if when else 'at an unknown time'}, "
        f"{len(old)} Creations)")
    if ov != nv:
        say(creations.clean(f"Catalog format version: {ov} -> {nv}"))
    for e in rep["added"]:
        say(creations.clean(f"ADDED   {creations.entry_text(e)}"))
    for e in rep["removed"]:
        say(creations.clean(f"REMOVED {creations.entry_text(e)}"))
    for u in rep["updated"]:
        say(creations.clean(f"UPDATED {u['title'] or '(no title)'} ({u['id']}): {creations.change_text(u['changes'])}"))
    say(f"Unchanged: {rep['unchanged']}. Timestamp-only changes (the game rewrites these when you load a save): "
        f"{rep['timestamp_only']}, not shown.")
    if n_changes:
        tail = ("The saved copy is now the current catalog." if args.save else
                "Run with --save to make this the new saved copy.")
        say(f"RESULT: CHANGES: {len(rep['added'])} added, {len(rep['removed'])} removed, {len(rep['updated'])} "
            f"updated. Test these Creations before you play; {tail[0].lower() + tail[1:]}")
    else:
        say("RESULT: NO CHANGES since the saved copy" + (" (saved again with --save)." if args.save else "."))
    return code


def cmd_fingerprint(args):
    dirs, _ = data_dirs(args) if (args.data or args.plugin_dir or not os.path.isfile(args.plugin)) else ([], None)
    path = args.plugin if os.path.isfile(args.plugin) else drift.find_file(args.plugin, dirs, "Plugin")
    plugin_module.check_copies(path)
    try:
        with Plugin(path, dirs) as p:
            probe, max_own = p.probe_ids()
    except (OSError, PluginError) as e:
        return fail(str(e))
    say(f"{os.path.basename(path)}: probe FormID {probe:06X} (highest own {'/'.join(sorted(PROBE_TYPES))} in its own "
        f"group), highest own FormID {max_own:06X} (over all records)")
    say_warnings()
    return 0


_JSON = [False]  # --json: the report is JSON only, so warnings go into it (drift check) or are left to the log


def say_warnings(always=False):
    if _JSON[0] and not always:
        return
    for w in plugin_module.warnings():
        say(f"WARNING: {w}")


def missing_step(args, drift_step=False):
    """A missing command or drift step: the help on stdout, then the RESULT line on stderr, exit 3."""
    is_drift = drift_step or getattr(args, "cmd", None) == "drift"
    try:
        build_parser().parse_args(["drift", "--help"] if is_drift else ["--help"])
    except SystemExit:
        pass
    sys.stdout.flush()  # the help first, so "see the help above" holds in a terminal
    what = ("no drift step given. Fix: run sf-patch-day drift init, snapshot or check" if is_drift else
            "no command given. Fix: run sf-patch-day dlls, drift, creations or fingerprint")
    print(f"RESULT: CANNOT CHECK: {what} (see the help above).", file=sys.stderr)
    return CANNOT


def main(argv=None):
    args = build_parser().parse_args(argv)
    # A missing command or drift step is a command-line mistake like the others: the help, then the RESULT line
    # on stderr, exit 3. (The bare "drift" command has no --verbose or --log, so this comes before the log.)
    if not args.cmd or (args.cmd == "drift" and not args.drift_cmd):
        return missing_step(args)
    plugin_module.clear_cache()
    _JSON[0] = bool(getattr(args, "json", False))
    log_open, code = False, CANNOT
    try:  # everything after this point ends in the finally below: the log closed and --json reset
        err = log.setup(args.verbose, args.log)
        if err:
            code = fail(err)
            return code
        log_open = True
        log.info("start", f"sf-patch-day {VERSION}, Python {sys.version.split()[0]}, {sys.platform}, "
                          f"args {argv or sys.argv[1:]}")
        code = {"dlls": cmd_dlls, "drift": cmd_drift, "creations": cmd_creations,
                "fingerprint": cmd_fingerprint}[args.cmd](args)
        return code
    except (drift.DriftError, creations.CreationsError) as e:
        code = fail(str(e))
        return code
    except KeyboardInterrupt:
        code = fail("stopped (Ctrl+C)")
        return code
    except Exception as e:  # last resort: one line for the reader, the traceback in the log
        log.info("error", traceback.format_exc())
        code = fail(f"unexpected error ({type(e).__name__}: {e}). Run again with --verbose and report the log at "
                    f"https://github.com/taosecurity/sf-patch-day/issues")
        return code
    finally:
        if log_open:  # the last log line says how the run ended (a log that never opened gets none)
            log.info("end", f"exit code {code}")
        log.close()
        _JSON[0] = False  # never carried into a later run in the same process
