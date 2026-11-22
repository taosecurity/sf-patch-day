# Changelog

## 0.2.1 (unreleased)

### What's new

sf-patch-day 0.2.1 makes `drift init` more exact about which quest stages your mod's scripts set. It no longer credits your mod with stages that a master's own script sets on a master record you override, and it says so when a record's fragment scripts can be read two ways. The format of the mods file hasn't changed.

### Example

This is the tool's real output on a made-up test mod whose dialogue record has a fragment section that fits both layouts:

    > .\sf-patch-day.cmd drift init ..\MyMod\MyMod.esm -o mods.json --data ..\Data --pex-tools ..\sf-pex-tools
    wrote mods.json: 1 overridden record(s), 0 master script function(s) your scripts call and 0 master quest(s) they set stages on, in 1 master(s)
      read 1 of your mod's own script(s) with sf-pex-tools 0.1.0 (..\sf-pex-tools)
      TestMaster.esm: 1 record(s)
    note: the fragment scripts of 1 INFO record(s) can be read two ways; the full entry (as xEdit reads it) layout was used, the usual one for INFO: 02000801
    Next: check the file, add anything else your mod relies on, then run drift snapshot (with sf-pex-tools, for the function checks).

### Fixes

- A master's attached script on a master record your plugin overrides no longer counts as yours when the master's copy of the record already has it with the same quest and stage properties. A script your plugin adds to the record, one whose quest or stage property your plugin changes, or your mod's own copy of it, still counts.
- When a master that could hold that record can't be read, the script still counts as yours, as in 0.2.0, since init can't tell whose it is.
- A script of your mod that wasn't read because of the safety limit (5,000 scripts) still counts as yours, so its quest stages on an overridden master record are kept.
- The safety limit's `note:` line counts only your mod's own unread scripts and says "at least". Before, it could count other mods' loose scripts. Past the limit, a loose script with no namespace that only your scripts' code reaches is neither read nor counted.
- The fragment count of a dialogue, package or scene record comes only from the flag bits that have a fragment (the low 2 for dialogue and scenes, the low 3 for packages), as xEdit reads it. A higher bit set by another tool no longer stops the rest of the record from being read.

### Changes

- When a record's fragment scripts can be read two ways (an empty fragment script name, which Mutagen and xEdit lay out differently), init still uses the usual layout for that record type and now says so in one `note:` line per record type (up to 20 FormIDs; the log lists them all). No record in the game's own plugins reads two ways.
- In the game's Data folder, a loose script with no namespace that your scripts call is no longer read as your mod's when all its functions are native (the script of an SFSE plugin, whose code is in its DLL). The mods file doesn't change; only the script count and the `note:` line do.
- The `--verbose` log says how each of these was decided.

### Download

Download `sf-patch-day-0.2.1.zip` and its `.sha256` file below, unzip it anywhere and follow the Install steps in the README. It needs Python 3.9 or newer and nothing else; sf-pex-tools 0.1.0 is optional.

## 0.2.0 (2026-11-21)

### What's new

sf-patch-day tells you, after a Starfield update, which of your SFSE plugins still load, and it tells mod authors whether the update changed anything their mod relies on. In 0.2.0, `drift init` reads your mod's compiled scripts. It adds the master script functions they call and the master quest stages they set to the mods file, so a script-only mod no longer starts with an empty file that has to be filled by hand.

This needs sf-pex-tools 0.1.0 in a folder next to sf-patch-day (or `--pex-tools <folder>`). Without it, init works as before and says how to get the script part.

### Example

    > .\sf-patch-day.cmd drift init ..\MyMod\MyMod.esm -o mods.json
    wrote mods.json: 0 overridden record(s), 40 master script function(s) your scripts call and 15 master quest(s) they set stages on, in 1 master(s)
      read 4 of your mod's own script(s) with sf-pex-tools 0.1.0 (C:\temp\patchday-example\sf-pex-tools)
      Starfield.esm: 15 record(s), 15 with quest stages, 40 function(s) in 15 script(s) from Starfield - Misc.ba2
    Next: check the file, add anything else your mod relies on, then run drift snapshot (with sf-pex-tools, for the function checks).

    > .\sf-patch-day.cmd drift snapshot --mods mods.json -o baseline.json
    Starfield.esm: 15 record(s) (0 not found), highest own FormID 3FFD59, probe 3FFD49, 40 function(s)
    wrote baseline.json

    > .\sf-patch-day.cmd drift check --mods mods.json --baseline baseline.json
    OK     Starfield.esm: unchanged since 2026-11-20 (MyMod.esm)
    RESULT: no change (exit 0)

The run is on a real Steam install, with a script-only mod of ours renamed MyMod.esm. In 0.1.3 the same mod gave an empty mods file. Every quest stage and function init found was then found again by snapshot in Starfield.esm and its scripts.

### How it works

- init reads the scripts the plugin names (attached scripts, and the fragment and alias scripts of quests, dialogue, scenes, packages, perks and terminal menus), the `.pex` files under `Scripts\` next to the plugin, and those in the mod's own `<Mod> - <name>.ba2` archives. When a Creations build folder also holds `_xbox` or `_ps5` archives, only the PC archive is read. The masters' scripts come from their own archives in the Data folder and `--plugin-dir` folders.
- Which copy of a script counts follows the game: a loose file beats every archive, and a later archive beats an earlier one. A changed copy of a master script that your mod ships is your mod's own script, and your mod is never listed as its own master.
- When the plugin is in the Data folder, `Data\Scripts` holds every mod's loose scripts. There a loose script counts as yours when its namespace is one your mod uses and no master uses, or, without a namespace or for a `Fragments:` script, when your plugin names it or one of your mod's own scripts uses it (a helper it calls, a parent it extends), and a `note:` line lists the ones taken in through your scripts. A loose copy of a master script there gets a `note:` line.
- Each master script function your scripts call is listed under the master script that defines it, with that master's archive in `ba2`. An inherited function goes under the parent script that defines it.
- A `note:` line says when a call passes a different number of arguments than the installed master's function takes, or calls a function no master script defines now. Either means the mod was built against another game version.
- Quests your scripts call `SetStage` or `SetCurrentStageID` on are listed with their stages when the quest is a script property your plugin fills. A quest your plugin overrides and attaches the script to counts too. Stages written in the script or filled as Int properties are listed, also when they are handed down through your script's own functions.
- A stage number worked out while the game runs (or above 65535) isn't listed, and the quest's `why` text says so. README "What init finds in your scripts" lists the other limits.
- The output is the same for the same mod and game files, and the file is valid against `examples/mods.schema.json`. The format of the mods file hasn't changed.

### Changes

- `drift init` has a `--pex-tools <folder>` option, like `snapshot` and `check`. A folder that doesn't hold sf-pex-tools stops init with exit 3 before anything is written.
- `drift init` refuses an existing output file (without `--force`) before it reads anything, instead of after.
- New tests build tiny made-up scripts, script data and archives, and use sf-pex-tools' own made-up test archive as the master's scripts. They skip without sf-pex-tools.

### Download

Download `sf-patch-day-0.2.0.zip` and its `.sha256` file below, unzip it anywhere and follow the Install steps in the README. It needs Python 3.9 or newer and nothing else; sf-pex-tools 0.1.0 is optional.

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
- `drift init` on a mod that changes no master records (many script-based mods) used to end with "Next: ... then run drift snapshot", and snapshot then refused the empty file with a general format message. Now init says the file has nothing to watch yet and what to add, and snapshot says the "masters" list is empty. The clean-folder test found this; a new test checks it.

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

This release has small fixes to the case-insensitive file name lookup added in 0.1.0 (used on Linux and Proton, where file names are case-sensitive but the game's aren't).

- When several files in a folder differ only in case, a WARNING names them and says the game may load another copy than the one checked. It shows in the normal output (once per file), also when a run fails (with or without `--json`), and `drift check` reports it at its own level, WARN (exit 1; level "WARN" in `--json` findings).
- A plugin given as a bare file name (run from its own folder) has its masters looked for in the current folder.
- A folder that can't be listed is logged and tried again on the next lookup, instead of being skipped for the rest of the run.
- A folder given two ways (a trailing slash, another case on Windows) is listed once.
- `drift snapshot`, `drift check` and `drift init` start with a fresh look at the folders even when called from another Python program.
- A test now runs the lookup as on a case-sensitive file system on every platform.

## 0.1.0 (2026-11-19)

This is the first release.

- `dlls` reads each SFSE plugin DLL's version data (from installed folders, single DLLs or zips) and gives one verdict per plugin for a game version: WORKS, NEEDS ADDRESS LIBRARY, MAY FAIL, NEEDS NEWER SFSE, LOCKED, NOT AN SFSE PLUGIN or UNREADABLE. It uses the same rule SFSE uses at startup. It reports the base layer too: the game version from Starfield.exe (or `--game-version`), SFSE for that version, and the Address Library file for it.
- `drift init`, `drift snapshot`, `drift check`: a mods file lists the records, quest stages and script functions a mod relies on in its masters; snapshot takes a baseline and check says whether an update changed them (exit 2 = rebuild). init writes a starting mods file from a mod's own overrides. Function checks use sf-pex-tools 0.1.0 when it's installed.
- `fingerprint` prints a plugin's probe FormID and highest own FormID, for in-game update checks.
- The tool has `--verbose` and `--log <file>`, `--json` (dlls, drift check), Steam and Game Pass found automatically, and MO2 and Vortex folders as options. It is read-only on the game folder and makes no network use.
- Names are matched the way the game matches them: Editor IDs, script paths, function names and plugin and archive file names ignore case, on Linux (Proton) too.
