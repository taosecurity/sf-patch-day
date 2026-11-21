# Changelog

## 0.1.3 (2026-11-20)

### What's new

This is a small maintenance release. sf-patch-day tells you, after a Starfield update, which of your SFSE plugins still load and what each one waits for, and it tells mod authors whether the update changed anything their mod relies on. In 0.1.3, `drift init` explains what to do when your mod changes no master records, the `drift` command handles a missing step in its own code, and the release was installed and run from a clean folder before it went out.

### Example

    > .\sf-patch-day.cmd drift init MyMod.esm -o mods.json
    wrote mods.json: 0 overridden record(s) in 0 master(s)
    note: the plugin overrides no master records with Editor IDs; add records your scripts use by hand
    Next: mods.json has nothing to watch yet. Add at least one master with the records, quest stages or script functions your mod relies on (README section 'The mods file', examples/mods.example.json), then run drift snapshot.

    > .\sf-patch-day.cmd drift snapshot --mods mods.json -o baseline.json
    RESULT: CANNOT CHECK: mods.json doesn't follow the mods file format:
      "masters" is empty, so there is nothing to watch: add at least one master with the records, quest stages or script functions your mod relies on
    Fix: see the README section 'The mods file' and examples/mods.example.json.

The run is on a real Steam install, with the mod's name changed.

### Fixes

- The `drift` command now answers a missing step (`sf-patch-day drift` alone) itself, with the help and a `RESULT: CANNOT CHECK` line, instead of relying on the main program to stop it first. Nothing changes for someone typing the command; another Python program that calls the `drift` code directly now gets the same answer instead of an error. A new test checks this.
- `drift init` on a mod that changes no master records (many script-based mods) used to end with "Next: ... then run drift snapshot", and snapshot then refused the empty file with a general format message. Now init says the file has nothing to watch yet and what to add, and snapshot says the "masters" list is empty. Found in the clean-folder test; a new test checks it.

### Download

Download `sf-patch-day-0.1.3.zip` and its `.sha256` file below, unzip it anywhere and follow the Install steps in the README. It needs Python 3.9 or newer and nothing else.

## 0.1.2 (2026-11-20)

### What's new

This is a small fix release. sf-patch-day tells you, after a Starfield update, which of your SFSE plugins still load and what each one waits for, and it tells mod authors whether the update changed anything their mod relies on. In 0.1.2, a command typed without its step now gets the help and a clear RESULT line instead of an unexpected error, and the troubleshooting log ends with the run's exit code.

### Example

    > .\sf-patch-day.cmd drift
    usage: sf-patch-day drift [-h] step ...

    positional arguments:
      step
        init      write a starting mods file from your mod's plugin
        snapshot  write a baseline from the installed masters
        check     compare the installed masters with the baseline

    options:
      -h, --help  show this help message and exit
    RESULT: CANNOT CHECK: no drift step given. Fix: run sf-patch-day drift init, snapshot or check (see the help above).

    > .\sf-patch-day.cmd dlls
    sf-patch-day 0.1.2 dlls
    Game version: 1.16.244 (read from C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe)
    SFSE: 0.2.21 for this game version found (sfse_1_16_244.dll)
    Address Library: versionlib-1-16-244-0.bin found (C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins)

    MAY FAIL               NewModA.dll
        'NewModA' by AuthorA, plugin version 110; signature scans; no game structures
        why: version independent by signature scans
        what to do: SFSE loads it; it works only if the code it searches for is unchanged. Test it, or check its page
    ...

    RESULT: some plugins wait for an update or need testing (may fail: 3, works: 12)

The `dlls` run is on a real Steam install, with mod and author names changed and the output shortened.

### Fixes

- `sf-patch-day` with no command, and `sf-patch-day drift` with no step, now print the help and then a `RESULT: CANNOT CHECK` line on stderr, like every other command-line mistake (exit 3). Before, `drift` with no step stopped with an "unexpected error".
- The troubleshooting log now ends with the run's exit code ("exit code 3") instead of "done". A log file that couldn't be opened gets no last line.
- A new test checks that a `--json` run doesn't change the output of a later run in the same process.

### Download

Download `sf-patch-day-0.1.2.zip` and its `.sha256` file below, unzip it anywhere and follow the Install steps in the README. It needs Python 3.9 or newer and nothing else.

## 0.1.1 (2026-11-20)

Small fixes to the case-insensitive file name lookup added in 0.1.0 (used on Linux and Proton, where file names
are case-sensitive but the game's aren't).

- When several files in a folder differ only in case, a WARNING names them and says the game may load another copy
  than the one checked. It shows in the normal output (once per file), also when a run fails (with or without
  `--json`), and `drift check` reports it at its own level, WARN (exit 1; level "WARN" in `--json` findings).
- A plugin given as a bare file name (run from its own folder) has its masters looked for in the current folder.
- A folder that can't be listed is logged and tried again on the next lookup, instead of being skipped for the
  rest of the run.
- A folder given two ways (a trailing slash, another case on Windows) is listed once.
- `drift snapshot`, `drift check` and `drift init` start with a fresh look at the folders even when called from
  another Python program.
- A test now runs the lookup as on a case-sensitive file system on every platform.

## 0.1.0 (2026-11-19)

First release.

- `dlls`: reads each SFSE plugin DLL's version data (from installed folders, single DLLs or zips) and gives one
  verdict per plugin for a game version: WORKS, NEEDS ADDRESS LIBRARY, MAY FAIL, NEEDS NEWER SFSE, LOCKED, NOT AN
  SFSE PLUGIN or UNREADABLE. It uses the same rule SFSE uses at startup. It reports the base layer too: the game
  version from Starfield.exe (or `--game-version`), SFSE for that version, and the Address Library file for it.
- `drift init`, `drift snapshot`, `drift check`: a mods file lists the records, quest stages and script functions
  a mod relies on in its masters; snapshot takes a baseline and check says whether an update changed them (exit 2
  = rebuild). init writes a starting mods file from a mod's own overrides. Function checks use sf-pex-tools 0.1.0
  when it's installed.
- `fingerprint`: a plugin's probe FormID and highest own FormID, for in-game update checks.
- `--verbose` and `--log <file>`, `--json` (dlls, drift check), Steam and Game Pass found automatically, MO2 and
  Vortex folders as options. Read-only on the game folder, no network use.
- Names are matched the way the game matches them: Editor IDs, script paths, function names and plugin and
  archive file names ignore case, on Linux (Proton) too.
