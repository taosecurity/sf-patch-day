# sf-patch-day: instructions for AI assistants

Follow these steps in order. Every command here has been run on the release.

## 1. What it's for, and when to use it

Use sf-patch-day after a Starfield game update, or before installing an SFSE plugin download, to answer:

- `dlls`: which SFSE plugin DLLs load on this game version, and what each waits for (SFSE, Address Library, its
  author).
- `drift`: for a mod author, whether an update changed the records, quest stages or script functions their mod
  relies on in a master plugin (exit 2 = rebuild).

Don't use it to edit plugins, turn mods on or off, or download anything. It does none of those.

## 2. Prerequisites

- Python 3.9 or newer (`python --version`). No other packages.
- Optional, for drift function checks only: sf-pex-tools 0.1.0 from
  https://github.com/taosecurity/sf-pex-tools/releases.

## 3. Install

1. Download `sf-patch-day-<version>.zip` and its `.sha256` from https://github.com/taosecurity/sf-patch-day/releases.
2. Check the hash: `certutil -hashfile sf-patch-day-0.1.3.zip SHA256` (Windows) or
   `sha256sum sf-patch-day-0.1.3.zip` (Linux). It must match the `.sha256` file.
3. Unzip it. The folder holds `sf-patch-day.py`, `sf-patch-day.cmd` and `sf_patch_day\`.
4. Optional: unzip sf-pex-tools 0.1.0 into a folder named `sf-pex-tools` next to the `sf-patch-day` folder.

## 4. Prove the install works

From the unzipped folder:

```
python -I tests/test_sf_patch_day.py
```

It must end with `OK` (some tests say `skipped` when sf-pex-tools isn't installed; that's fine). Then
`python -I sf-patch-day.py --version` prints `sf-patch-day 0.1.3`.

## 5. Common tasks

Run commands from the unzipped folder. On Windows, `sf-patch-day.cmd` can replace `python -I sf-patch-day.py`.
Options go after the command name.

| Task | Command |
|---|---|
| Check installed SFSE plugins | `python -I sf-patch-day.py dlls` |
| Check a download before installing it | `python -I sf-patch-day.py dlls "<path to the .zip>"` |
| Judge against a version not installed yet | `python -I sf-patch-day.py dlls --game-version 1.16.250` |
| Name the game folder | `python -I sf-patch-day.py dlls --game "<folder holding Starfield.exe>"` |
| Check a Mod Organizer 2 mods folder | `python -I sf-patch-day.py dlls "%LOCALAPPDATA%\ModOrganizer\Starfield\mods"` |
| Machine-readable report | add `--json` (dlls, drift check) |
| Start a mods file from a mod's plugin | `python -I sf-patch-day.py drift init "<MyMod.esm>" -o mods.json` |
| Take a baseline | `python -I sf-patch-day.py drift snapshot --mods mods.json -o baseline.json` |
| Check after an update | `python -I sf-patch-day.py drift check --mods mods.json --baseline baseline.json` |
| Masters in a mod manager folder | add `--plugin-dir "<folder>"` (drift, fingerprint; repeatable) |
| Probe FormIDs for in-game checks | `python -I sf-patch-day.py fingerprint "<Plugin.esm>"` |

The mods file format is in README.md ("The mods file") and `examples/mods.schema.json`. After `drift init`, the
author must add quest stages and script functions by hand; init only finds overridden records. When init finds
nothing it can watch by name (no overridden master records with Editor IDs, or none whose master the plugin lists;
the second case prints its own note and means the plugin is damaged), init still exits 0 but writes an empty `"masters"` and says "has nothing
to watch yet"; `drift snapshot` refuses that file (exit 3) until at least one entry is added.

## 6. Inputs, outputs, exit codes and the log

- Inputs: DLLs, zips and folders (dlls); a mods file, a baseline, the game's Data folder and optional
  `--plugin-dir` folders (drift).
- Outputs: a report on stdout. The text reports of `dlls` and `drift check`, and every failed run, end with a
  `RESULT:` line. With `--json` a finished run prints only its JSON report (`dlls --json` can do so with exit 3,
  naming unreadable files under `problems`); a run that stops before its report prints plain text (WARNING lines,
  then `RESULT: CANNOT CHECK`) on stdout, and a command-line mistake prints `RESULT: CANNOT CHECK` on stderr. Judge
  a run by its exit code; try to parse stdout as JSON, and fall back to the text when that fails. `drift init` writes the mods file you
  name; `drift snapshot` writes the baseline you name. Both refuse to overwrite without `--force` and refuse to
  write inside the game folder. Nothing else is written. Never rerun `snapshot --force` in place of `check` after
  an update: that replaces the baseline the check needs.
- Exit codes: dlls 0 all work, 1 some need Address Library / may fail / need newer SFSE / SFSE missing, 2 some
  locked or a Game Pass install, 3 can't read or bad command. drift check 0 no change, 1 changed but unused, a name to check, a check skipped or a WARN about copies of a file,
  2 rebuild, 3 can't read or bad command. init, snapshot and fingerprint: 0 done, 3 problem.
- Log: `--verbose` writes it to stderr; `--log <file>` writes it to a file. Off unless asked.

## 7. Limits

- Read-only on the game folder. Never uploads anything; no network use at all.
- Applies SFSE's loading rule only. A plugin that passes can still misbehave in game; "MAY FAIL" needs a test.
- Doesn't judge DLLs without SFSE version data (ASI plugins, proxy DLLs).
- SFSE doesn't support the Game Pass version of Starfield; dlls says so on Game Pass installs.
- drift sees only what the mods file lists. It doesn't read the mod's scripts.
