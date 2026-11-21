# sf-patch-day

sf-patch-day tells you, after a Starfield update, which of your SFSE plugins still load and what each one waits
for. For mod authors, it also says whether the update changed anything your mod relies on, so you know whether to
rebuild it.

Download the latest zip from [Releases](https://github.com/taosecurity/sf-patch-day/releases), unzip it, open a
Command Prompt in the folder (see [Install](#install)) and run:

```
.\sf-patch-day.cmd dlls
```

For AI assistants: step-by-step instructions are in [AGENTS.md](AGENTS.md).

## Example

This is a real run on a Steam install with 15 SFSE plugins (mod and author names changed, and the output
shortened):

```
> .\sf-patch-day.cmd dlls
sf-patch-day 0.1.3 dlls
Game version: 1.16.244 (read from C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe)
SFSE: 0.2.21 for this game version found (sfse_1_16_244.dll)
Address Library: versionlib-1-16-244-0.bin found (C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins)

MAY FAIL               NewModA.dll
    'NewModA' by AuthorA, plugin version 110; signature scans; no game structures
    why: version independent by signature scans
    what to do: SFSE loads it; it works only if the code it searches for is unchanged. Test it, or check its page
WORKS                  NewModB.dll
    'NewModB' by AuthorB, plugin version 1.4.17; Address Library; 1.14.70+ structure layout
    why: lists 1.16.244
WORKS                  NewModC.dll
    'NewModC' by AuthorC, plugin version 21.7.0; fixed addresses; no structure promise
    why: lists 1.16.244
...

RESULT: some plugins wait for an update or need testing (may fail: 3, works: 12)
```

The first three lines are the base layer that every plugin needs: the game version, SFSE for that version, and the
Address Library file for it. Then each plugin gets a verdict, a reason and, when there is something to do, what to
do. Twelve plugins work, and three find the game's code by searching for it, so they need a quick test after an
update. The last line sums it up, and the exit code (1 here) says the same thing to scripts.

What it promises:

- It only reads. It never changes anything in the game folder, and it refuses to write its own files there.
- It never connects to the internet.
- It works with Steam and Game Pass installs, and with mods managed by Mod Organizer 2 or Vortex.
- It runs on Windows and Linux (Proton installs too), with Python 3.9 or newer and nothing else.

This tool was built with [Claude Code](https://claude.com/claude-code).

## Contents

- [Install](#install)
- [Words used here](#words-used-here)
- [dlls: which SFSE plugins still load](#dlls-which-sfse-plugins-still-load)
- [drift: does my mod need a rebuild](#drift-does-my-mod-need-a-rebuild)
- [The mods file](#the-mods-file)
- [fingerprint](#fingerprint)
- [Where things are: Steam, Game Pass, MO2 and Vortex](#where-things-are-steam-game-pass-mo2-and-vortex)
- [Exit codes](#exit-codes)
- [Logs](#logs)
- [Limits](#limits)
- [Found a mistake?](#found-a-mistake)
- [Credits and license](#credits-and-license)

## Install

sf-patch-day is a Python program that uses only Python's standard library, so there is nothing else to install. It
needs Python 3.9 or newer.

1. Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/). On the first screen of the
   installer, tick **Add python.exe to PATH**. To check that it worked, open a new Command Prompt and type
   `python --version`. It should print a version number.
2. Download `sf-patch-day-0.1.3.zip` and its `.sha256` file from the
   [releases page](https://github.com/taosecurity/sf-patch-day/releases) and unzip the zip anywhere. If you want
   to check the download, run `certutil -hashfile sf-patch-day-0.1.3.zip SHA256` (on Linux,
   `sha256sum sf-patch-day-0.1.3.zip`) and compare the result with the `.sha256` file.
3. Open the unzipped folder in File Explorer, click the address bar at the top, type `cmd` and press Enter. A
   Command Prompt window opens in that folder, ready for the commands in this README.
4. Run `.\sf-patch-day.cmd --version`. It should print `sf-patch-day 0.1.3`.

`.\sf-patch-day.cmd` works in both Command Prompt and PowerShell. It only starts `python -I sf-patch-day.py` with the
options you give it, so on Linux type `python3 -I sf-patch-day.py` instead. To check the install
fully, run the tests: `python -I tests/test_sf_patch_day.py`. They end with `OK`.

**Optional, for `drift` function checks only:** download [sf-pex-tools 0.1.0](https://github.com/taosecurity/sf-pex-tools/releases)
the same way and unzip it into a folder named `sf-pex-tools` next to the `sf-patch-day` folder. You can also point
to it with `--pex-tools <folder>` or the `SF_PEX_TOOLS` environment variable.

## Words used here

- **SFSE:** the Starfield Script Extender, which loads `.dll` plugins that add features the game lacks. Each game
  update can break them until they are updated. The game must be started through SFSE for them to load.
- **SFSE plugin:** a `.dll` file in the game's `Data\SFSE\Plugins` folder that SFSE loads when the game starts.
- **Address Library:** a data file that many SFSE plugins use to find game functions after an update. It has one
  file per game version, such as `versionlib-1-16-244-0.bin`.
- **Signature scans:** another way for a plugin to find the game's code, by searching for known byte patterns. It
  needs no Address Library, but it fails if an update changed those bytes.
- **Plugin:** a mod's data file (`.esm`, `.esp` or `.esl`). It adds or changes records in the game.
- **Master:** a plugin that another plugin needs loaded before it. Starfield.esm is the master of nearly every mod.
- **Record:** one thing in a plugin, such as a weapon, a quest, a location or a setting.
- **FormID:** a record's number, such as `0002B560`. The first two digits depend on the load order.
- **Editor ID:** a record's readable name, such as `MQ101`, used by the Creation Kit and xEdit.
- **Quest stage:** a numbered step of a quest. Scripts move a quest on by setting its stages.
- **BA2:** Bethesda's archive format. Mods pack their scripts, models and textures into `.ba2` files.
- **Papyrus:** Starfield's scripting language. Scripts are compiled into `.pex` files that the game runs, and a
  script's functions can be called by other mods' scripts.
- **Creation:** a mod published on Bethesda's own Creations store.

## dlls: which SFSE plugins still load

Each SFSE plugin DLL carries a small block of version data. It says which game versions the plugin supports and how
it finds the game's code. SFSE reads it when the game starts and turns off plugins that don't fit. sf-patch-day
applies the same rule before you launch, either for the plugins you have installed or for a download you're about to
install.

```
.\sf-patch-day.cmd dlls                                  your installed plugins (the game's Data\SFSE\Plugins)
.\sf-patch-day.cmd dlls "Downloads\SomePlugin-1.2.zip"   a download, before you install it
.\sf-patch-day.cmd dlls --game-version 1.16.250          judge your plugins against a version you don't have yet
```

First it reports the base layer:

- **Game version**, read from `Starfield.exe` (or given with `--game-version`).
- **SFSE** for that version (`sfse_1_16_244.dll` for 1.16.244). If it's missing, every SFSE plugin waits for an
  SFSE update.
- **Address Library** file for that version (`versionlib-1-16-244-0.bin`), searched in what you gave and in the
  game's plugin folder.

Then it gives one verdict per DLL:

| Verdict | What it means | What to do |
|---|---|---|
| WORKS | It lists this game version, or it's version independent and what it needs is present. | Nothing. |
| NEEDS ADDRESS LIBRARY | It finds the game's code through Address Library, and the file for this version isn't installed. | Install the new Address Library file when it's released. |
| MAY FAIL | It finds the game's code by searching for byte patterns, so SFSE loads it on any version. | It works only if those patterns are unchanged: test it, or check its page. |
| NEEDS NEWER SFSE | It asks for a newer SFSE than the one installed. | Update SFSE. |
| LOCKED | SFSE refuses it on this version. | Turn it off until its author releases an update. |
| NOT AN SFSE PLUGIN | No SFSE version data (an ASI plugin, a helper DLL, a proxy DLL, or SFSE itself). | Not judged. |
| UNREADABLE | Damaged, or not a Windows DLL. | Download it again. |

Each line also shows the plugin's own name, author and version, and how it finds the game's code. A **hint** line
appears when a DLL's code names an Address Library file but its version data doesn't say so.

Here is the same install from the [Example](#example), judged against a game version that isn't out yet (mod and
author names changed, output shortened):

```
> .\sf-patch-day.cmd dlls --game-version 1.16.250
sf-patch-day 0.1.3 dlls
Game version: 1.16.250 (given with --game-version)
SFSE: NOT FOUND for this game version (sfse_1_16_250.dll is missing). Every SFSE plugin waits for an SFSE update from its authors.
Address Library: versionlib-1-16-250-0.bin NOT FOUND in the folders checked (plugins that use it wait for its update)

LOCKED                 MyMod.dll
    'MyMod' by MyName, plugin version 2; Address Library; no structure promise
    why: lists only 1.16.244 (it uses Address Library but makes no structure promise, so SFSE treats it as locked)
    what to do: SFSE refuses it on this game version: turn it off until its author releases an update
NEEDS ADDRESS LIBRARY  NewModB.dll
    'NewModB' by AuthorB, plugin version 1.4.17; Address Library; 1.14.70+ structure layout
    why: uses Address Library; versionlib-1-16-250-0.bin was not found
    what to do: install the Address Library file for this game version when its author releases it
...

RESULT: some plugins are locked to other game versions (locked: 7, needs address library: 4, may fail: 4)
```

Options:

- `--game <folder>`: the folder holding `Starfield.exe`.
- `--game-version X.Y.Z`: judge against this version instead of the installed one.
- `--json`: print the report as JSON.
- `--verbose`, `--log <file>`: write a troubleshooting log (see [Logs](#logs)).

Paths can be DLLs, zips or folders. Folders are searched, including any zips inside them.

## drift: does my mod need a rebuild

This part is for mod authors whose mod builds on records in another plugin: Starfield.esm, a DLC such as Shattered
Space, a Creation, or another author's mod. You list the records, quest stages and script functions your mod uses.
sf-patch-day takes a baseline and, after an update, tells you whether any of them changed.

```
.\sf-patch-day.cmd drift init MyMod.esm -o mods.json                       1. a starting list from your plugin
.\sf-patch-day.cmd drift snapshot --mods mods.json -o baseline.json         2. the baseline, while your mod works
.\sf-patch-day.cmd drift check --mods mods.json --baseline baseline.json    3. after each game or Creation update
```

1. `init` lists every master record your plugin overrides (ships a changed copy of). Any change to those means
   rebuild. It can't see what your scripts use, so add those by hand (see [The mods file](#the-mods-file)). When
   init finds nothing it can watch by name (no overridden master records with Editor IDs, or none whose master the
   plugin lists, which it notes as possibly damaged or unusual), it writes a mods file with nothing in it yet and
   says so: add at least one entry before you run `snapshot`.
2. `snapshot` records facts about each listed record: its FormID, type, a hash of its contents, its quest stages
   and condition count, and the argument count of each listed script function. Take it when your mod is built and
   working. Keep `mods.json` and `baseline.json` with your mod's source.
3. `check` compares the installed masters with the baseline.

A real run, with a mods file that lists one quest and one global from Starfield.esm:

```
> .\sf-patch-day.cmd drift snapshot --mods mods.json -o baseline.json
Starfield.esm: 2 record(s) (0 not found), highest own FormID 3FFD59, probe 3FFD49
wrote baseline.json

> .\sf-patch-day.cmd drift check --mods mods.json --baseline baseline.json
OK     Starfield.esm: unchanged since 2026-11-20 (MyMod.esm)
RESULT: no change (exit 0)
```

Each line of a `check` report starts with a level:

- `OK`: the master file is unchanged.
- `NOTE`: the master changed, but not in anything your mod uses, or a name in your mods file needs checking. It's
  worth a look, but no rebuild is needed.
- `WARN`: a folder holds several files whose names differ only in case (Linux and Proton), so the game may load a
  different copy than the one checked. Remove the extra copies.
- `ACTION`: something your mod uses changed. A copied record changed, a record or quest stage is gone, a FormID
  moved, or a script function is gone or takes a different number of arguments. Rebuild, and retest. The last line
  then reads `RESULT: ACTION NEEDED: rebuild the mods named above (exit 2)`.
- `SKIP`: a check couldn't run (function checks without sf-pex-tools).

Options:

- `--data <folder>`: the game's Data folder (found automatically).
- `--plugin-dir <folder>`: a folder searched first for masters. Repeat it for several.
- `--pex-tools <folder>`: where sf-pex-tools is.
- `--json`: print the `check` report as JSON.
- `--force`: let `init` and `snapshot` overwrite their files. Take a new baseline only after you rebuild your mod,
  never instead of `check`.
- `--verbose`, `--log <file>`: write a troubleshooting log.

Names are matched the way the game matches them: Editor IDs, script paths and function names ignore case, and
record types are read in upper case. A record, stage, script or function that is missing now and was also missing
when you took the baseline is a `NOTE` (check the name), not a rebuild.

The baseline holds only sizes, hashes, FormIDs, stage numbers, condition counts and function names. It never holds
record contents or script code, so you can keep it in a public repository.

## The mods file

The mods file is a JSON file that lists what your mod relies on. [examples/mods.example.json](examples/mods.example.json)
is a made-up example, and [examples/mods.schema.json](examples/mods.schema.json) describes the format.

```json
{
 "mod": "MyQuestTweaks.esm",
 "masters": {
  "ExampleCreation.esm": {
   "ba2": "ExampleCreation - Main.ba2",
   "records": [
    {"edid": "EC_StartConditions", "type": "CNDF", "copied": true},
    {"edid": "EC_MainQuest01", "type": "QUST", "stages": [100, 200]}
   ],
   "functions": {"scripts/ExampleCreation/EC_MainQuest01Script.pex": ["GiveReward"]}
  }
 }
}
```

- `masters`: one entry per master plugin, by file name.
- `records`: each record your mod relies on, by Editor ID. Set `copied: true` when your plugin ships a copy of it,
  and list in `stages` the quest stages your scripts set.
- `type` (four letters, such as QUST) is optional. When every record has one, scanning a big master such as
  Starfield.esm is much faster. `why` and `used_by` are notes shown in the report.
- `functions`: the master's script functions your scripts call by name, listed by script path inside `ba2`. These
  checks need sf-pex-tools.

## fingerprint

`fingerprint` prints two FormIDs of a plugin: its probe FormID and its highest own FormID. The probe is its newest
record of a type that `Game.GetFormFromFile` always finds (QUST, GLOB, KYWD, FLST, MISC or WEAP, in its own group).
A mod that checks in game whether a master has been updated can probe the FormID just above these: if it exists,
the master has new records.

```
> .\sf-patch-day.cmd fingerprint ShatteredSpace.esm
ShatteredSpace.esm: probe FormID 176200 (highest own FLST/GLOB/KYWD/MISC/QUST/WEAP in its own group), highest own FormID 1764C2 (over all records)
```

## Where things are: Steam, Game Pass, MO2 and Vortex

Without `--game` or `--data`, sf-patch-day looks for the game in this order:

1. **Steam:** the Steam folder from the registry and `C:\Program Files (x86)\Steam`, plus every library in
   `steamapps\libraryfolders.vdf`, as `<library>\steamapps\common\Starfield`. On Linux: `~/.steam/steam`,
   `~/.local/share/Steam` and the Flatpak Steam folder.
2. **Game Pass:** `<drive>:\XboxGames\Starfield\Content` on every drive. SFSE doesn't support the Game Pass
   version, so `dlls` says so. `drift` works normally.

Mod managers keep mods outside the game folder until they deploy them:

- **Mod Organizer 2:** each mod is a folder under `mods\` (by default in `%LOCALAPPDATA%\ModOrganizer\Starfield`,
  or next to `ModOrganizer.exe` for a portable install). Check them with
  `.\sf-patch-day.cmd dlls "%LOCALAPPDATA%\ModOrganizer\Starfield\mods"`, and give a master that lives in a mod folder to
  drift with `--plugin-dir "<that mod's folder>"`.
- **Vortex:** the staging folder, by default `%APPDATA%\Vortex\starfield\mods\<mod name>\`, or the deployed copy in
  the game's Data folder (the default).

## Exit codes

| Code | dlls | drift check |
|---|---|---|
| 0 | Every plugin checked works. | No change. |
| 1 | Some plugins need Address Library, may fail, or need a newer SFSE, or SFSE for this version is missing. | A master changed, but nothing your mod uses; a name to check; a check was skipped; or a WARN about copies of a file. |
| 2 | At least one plugin is locked to other game versions, or the install is Game Pass (SFSE doesn't run there). | Rebuild: something your mod uses changed. |
| 3 | A file couldn't be read, or the command was wrong. | A file couldn't be read, or the command was wrong. |

`drift init`, `drift snapshot` and `fingerprint` return 0 on success and 3 on a problem. Scripts should rely on the
exit code. The rest of this section is for people who read the output from a script:

- The text reports of `dlls` and `drift check`, and every failed run, end with a `RESULT:` line.
- With `--json`, a finished report is JSON only, with the exit code in its `exit` field. `dlls --json` can return
  such a report with exit 3, listing the files it couldn't read under `problems`.
- A run that stops before its report prints plain text instead, even with `--json`: any WARNING lines about copies
  of a file, then `RESULT: CANNOT CHECK` on stdout.
- A command-line mistake (an unknown option, a missing argument) prints its `RESULT: CANNOT CHECK` line on stderr.

## Logs

Add `--verbose` to write a troubleshooting log to the screen (stderr), or `--log <file>` to write it to a file. It
records what was read (files, versions, flags), each decision and why, and the full error on a crash. It ends with
the run's exit code. Nothing is logged unless you ask. Include the log when you report a problem.

## Limits

- `dlls` applies SFSE's own loading rule. A plugin that passes it can still misbehave if the update changed the
  game code it patches, and only its author can say. "MAY FAIL" plugins need a test.
- It doesn't judge DLLs without SFSE version data (ASI plugins, proxy DLLs).
- `drift` sees only what you list (plus the overrides `init` finds). It doesn't read your scripts.
- It doesn't download updates, and it doesn't turn plugins off for you.

## Found a mistake?

Open an issue: https://github.com/taosecurity/sf-patch-day/issues. Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## Credits and license

sf-patch-day was made by Richard Bejtlich. It applies the plugin loading rule of
[SFSE](https://sfse.silverlock.org), the Starfield Script Extender, and reads the Address Library files that SFSE
plugin authors use; it ships neither. Script function checks use
[sf-pex-tools](https://github.com/taosecurity/sf-pex-tools) when it's installed. Starfield belongs to Bethesda
Softworks, and sf-patch-day ships no game files.

sf-patch-day is released under the MIT license (see [LICENSE](LICENSE)).
