# sf-patch-day

After a Starfield update, run this to see which of your SFSE plugins still load, and whether your mod needs a
rebuild.

```
sf-patch-day dlls
```

It answers two questions:

- **`dlls`: which SFSE plugins does this game version break?** Each SFSE plugin DLL carries a small block of
  version data that says which game versions it supports and how it finds the game's code. SFSE reads it when the
  game starts and turns off plugins that don't fit. sf-patch-day applies the same rule before you launch, for the
  plugins you have installed or for a download you're about to install. It also checks the two things every plugin
  waits for: SFSE itself for the new game version, and the Address Library file for that version.
- **`drift`: did the update change what my mod relies on?** (for mod authors) You list the records, quest
  stages and script functions your mod uses from Starfield, a DLC, a Creation or another mod. sf-patch-day takes a
  baseline and, after an update, tells you whether any of them changed. Exit code 2 means rebuild.

What it promises:

- It only reads. It never changes anything in the game folder, and it refuses to write its own files there.
- It never connects to the internet.
- It works with Steam and Game Pass installs, and with mods managed by Mod Organizer 2 or Vortex.
- It runs on Windows and Linux (Proton installs too), with Python 3.9 or newer and nothing else.
- It's released under the MIT license.

This tool was built with [Claude Code](https://claude.com/claude-code).

For AI assistants: see [AGENTS.md](AGENTS.md) for step-by-step instructions.

## Contents

- [Install](#install)
- [dlls: which SFSE plugins still load](#dlls-which-sfse-plugins-still-load)
- [drift: does my mod need a rebuild](#drift-does-my-mod-need-a-rebuild)
- [The mods file](#the-mods-file)
- [fingerprint](#fingerprint)
- [Where things are: Steam, Game Pass, MO2 and Vortex](#where-things-are-steam-game-pass-mo2-and-vortex)
- [Exit codes](#exit-codes)
- [Logs](#logs)
- [Limits](#limits)

## Install

1. Install Python 3.9 or newer from https://www.python.org (on Windows, tick "Add python.exe to PATH").
2. Download `sf-patch-day-<version>.zip` from the [releases page](https://github.com/taosecurity/sf-patch-day/releases),
   check it against the `.sha256` file next to it, and unzip it anywhere:

   ```
   certutil -hashfile sf-patch-day-0.1.2.zip SHA256
   ```

   On Linux, use `sha256sum sf-patch-day-0.1.2.zip`.
3. Optional, for `drift` function checks only: download [sf-pex-tools 0.1.0](https://github.com/taosecurity/sf-pex-tools/releases)
   the same way and unzip it into a folder named `sf-pex-tools` next to the `sf-patch-day` folder (or point to it
   with `--pex-tools <folder>` or the `SF_PEX_TOOLS` environment variable).

Run it with `sf-patch-day.cmd` on Windows, or `python -I sf-patch-day.py` anywhere. Check the install with the
tests: `python -I tests/test_sf_patch_day.py`.

## dlls: which SFSE plugins still load

```
sf-patch-day dlls                                  your installed plugins (the game's Data\SFSE\Plugins)
sf-patch-day dlls "Downloads\SomePlugin-1.2.zip"   a download, before you install it
sf-patch-day dlls --game-version 1.16.250          judge your plugins against a version you don't have yet
```

First it reports the base layer:

- **Game version**, read from `Starfield.exe` (or given with `--game-version`).
- **SFSE** for that version (`sfse_1_16_244.dll` for 1.16.244). If it's missing, every SFSE plugin waits for an
  SFSE update.
- **Address Library** file for that version (`versionlib-1-16-244-0.bin`), searched in what you gave and in the
  game's plugin folder.

Then one verdict per DLL:

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

Options: `--game <folder>` (the folder holding `Starfield.exe`), `--game-version X.Y.Z`, `--json`, `--verbose`,
`--log <file>`. Paths can be DLLs, zips or folders (folders are searched, including zips inside them).

## drift: does my mod need a rebuild

For mod authors whose mod builds on records in another plugin: Starfield.esm, a DLC such as Shattered Space, a
Creation, or another author's mod.

```
sf-patch-day drift init MyMod.esm -o mods.json                       1. a starting list from your plugin
sf-patch-day drift snapshot --mods mods.json -o baseline.json         2. the baseline, while your mod works
sf-patch-day drift check --mods mods.json --baseline baseline.json    3. after each game or Creation update
```

1. `init` lists every master record your plugin overrides (ships a changed copy of). Any change to those means
   rebuild. It can't see what your scripts use, so add those by hand (next section).
2. `snapshot` records facts about each listed record: its FormID, type, a hash of its contents, its quest stages
   and condition count, and the argument count of each listed script function. Take it when your mod is built and
   working. Keep `mods.json` and `baseline.json` with your mod's source.
3. `check` compares the installed masters with the baseline:

   - `OK`: the master file is unchanged.
   - `NOTE`: the master changed, but nothing your mod uses, or a name in your mods file to check (worth a look; no
     rebuild).
   - `WARN`: a folder holds several files whose names differ only in case (Linux and Proton), so the game may load
     a different copy than the one checked. Remove the extra copies.
   - `ACTION`: something your mod uses changed: a copied record changed, a record or quest stage is gone, a FormID
     moved, or a script function is gone or takes a different number of arguments. Rebuild, and retest.
   - `SKIP`: a check couldn't run (function checks without sf-pex-tools).

Options: `--data <folder>` (the game's Data folder; found automatically), `--plugin-dir <folder>` (searched first;
repeat it for several), `--pex-tools <folder>`, `--json` (check), `--force` (init and snapshot, to overwrite; take a new baseline only after you rebuild your mod,
never instead of `check`), `--verbose`, `--log <file>`.

Names are matched the way the game matches them: Editor IDs, script paths and function names ignore case, and
record types are read in upper case. A record, stage, script or function that is missing now and was also missing
when you took the baseline is a `NOTE` (check the name), not a rebuild.

The baseline holds only sizes, hashes, FormIDs, stage numbers, condition counts and function names. It never holds
record contents or script code, so you can keep it in a public repository.

## The mods file

A JSON file. [examples/mods.example.json](examples/mods.example.json) is a made-up example, and
[examples/mods.schema.json](examples/mods.schema.json) describes the format.

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
- `records`: each record your mod relies on, by Editor ID. `copied: true` when your plugin ships a copy of it.
  `stages`: the quest stages your scripts set. `type` (four letters, such as QUST) is optional, but when every
  record has one, scanning a big master such as Starfield.esm is much faster. `why` and `used_by` are notes shown
  in the report.
- `functions`: the master's script functions your scripts call by name, by script path inside `ba2`. Needs
  sf-pex-tools.

## fingerprint

```
sf-patch-day fingerprint ShatteredSpace.esm
```

Prints a plugin's probe FormID (its newest record of a type `Game.GetFormFromFile` always finds: QUST, GLOB, KYWD,
FLST, MISC or WEAP, in its own group) and its highest own FormID. A mod that checks in game whether a master has
been updated can probe the FormID just above these: if it exists, the master has new records.

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
  `sf-patch-day dlls "%LOCALAPPDATA%\ModOrganizer\Starfield\mods"`, and give a master that lives in a mod folder to
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

`drift init`, `drift snapshot` and `fingerprint` return 0 on success and 3 on a problem. The text reports of `dlls`
and `drift check`, and every failed run, end with a `RESULT:` line; with `--json` a finished report is JSON only,
with the exit code in its `exit` field (`dlls --json` can return such a report with exit 3, listing the files it
couldn't read under `problems`). A run that stops before its report prints plain text instead, even with
`--json`: any WARNING lines about copies of a file, then `RESULT: CANNOT CHECK` on stdout. A command-line mistake
(an unknown option, a missing argument) prints its `RESULT: CANNOT CHECK` line on stderr. Scripts should rely on
the exit code.

## Logs

Add `--verbose` to write a troubleshooting log to the screen (stderr), or `--log <file>` to write it to a file. It
records what was read (files, versions, flags), each decision and why, and the full error on a crash. Nothing is
logged unless you ask. Include the log when you report a problem at
https://github.com/taosecurity/sf-patch-day/issues.

## Limits

- `dlls` applies SFSE's own loading rule. A plugin that passes it can still misbehave if the update changed the
  game code it patches; only its author can say. "MAY FAIL" plugins need a test.
- It doesn't judge DLLs without SFSE version data (ASI plugins, proxy DLLs).
- `drift` sees only what you list (plus overrides `init` finds). It doesn't read your scripts.
- It doesn't download updates, and it doesn't turn plugins off for you.
