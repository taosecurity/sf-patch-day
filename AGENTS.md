# sf-patch-day: instructions for AI assistants

Follow these steps in order. Every command here has been run on the release.

## 1. What it's for, and when to use it

Use sf-patch-day after a Starfield game update, or before installing an SFSE plugin download, to answer:

- `dlls`: which SFSE plugin DLLs load on this game version, and what each waits for (SFSE, Address Library, its
  author). It also says which framework each plugin was built with (CommonLibSF, plain SFSE or can't tell) and
  whether it shows signs of using Address Library. Each readable DLL also gets a "risk evidence" line (network,
  process launch, runtime DLL loading and code patching imports), "signature scans" is printed only with signs of
  a pattern scanner (else "says signature scans, but no pattern-scan signs found"), and a "can't tell" plugin gets
  a "framework hints" line.
- `drift`: for a mod author, whether an update changed the records, quest stages or script functions their mod
  relies on in a master plugin (exit 2 = rebuild).
- `creations`: which Creations were added, removed or updated (version, title, files, size, achievement-friendly)
  since a copy of the game's `ContentCatalog.txt` saved on an earlier run.

Don't use it to edit plugins, turn mods on or off, or download anything. It does none of those.

## 2. Prerequisites

- Python 3.9 or newer (`python --version`). No other packages.
- Optional, for drift only (init reading the mod's scripts, and the function checks of snapshot and check):
  sf-pex-tools 0.1.0 from https://github.com/taosecurity/sf-pex-tools/releases.

## 3. Install

1. Download `sf-patch-day-<version>.zip` and its `.sha256` from https://github.com/taosecurity/sf-patch-day/releases.
2. Check the hash: `certutil -hashfile sf-patch-day-0.5.3.zip SHA256` (Windows) or
   `sha256sum sf-patch-day-0.5.3.zip` (Linux). It must match the `.sha256` file.
3. Unzip it. The folder holds `sf-patch-day.py`, `sf-patch-day.cmd` and `sf_patch_day\`.
4. Optional: unzip sf-pex-tools 0.1.0 into a folder named `sf-pex-tools` next to the `sf-patch-day` folder.

## 4. Prove the install works

From the unzipped folder:

```
python -I tests/test_sf_patch_day.py
```

It must end with `OK` (some tests say `skipped` when sf-pex-tools isn't installed; that's fine). Then
`python -I sf-patch-day.py --version` prints `sf-patch-day 0.5.3`.

## 5. Common tasks

Run commands from the unzipped folder. On Windows, `sf-patch-day.cmd` can replace `python -I sf-patch-day.py`.
Options go after the command name.

| Task | Command |
|---|---|
| Check installed SFSE plugins | `python -I sf-patch-day.py dlls` |
| Check a download before installing it | `python -I sf-patch-day.py dlls "<path to the .zip>"` |
| Check one DLL (verdict and framework) | `python -I sf-patch-day.py dlls "<path to the .dll>"` |
| Judge against a version not installed yet | `python -I sf-patch-day.py dlls --game-version 1.16.250` |
| Name the game folder | `python -I sf-patch-day.py dlls --game "<folder holding Starfield.exe>"` |
| Check a Mod Organizer 2 mods folder | `python -I sf-patch-day.py dlls "%LOCALAPPDATA%\ModOrganizer\Starfield\mods"` |
| Machine-readable report | add `--json` (dlls, drift check, creations) |
| Start a mods file from a mod's plugin | `python -I sf-patch-day.py drift init "<MyMod.esm>" -o mods.json` |
| The same, naming the sf-pex-tools folder | `python -I sf-patch-day.py drift init "<MyMod.esm>" -o mods.json --pex-tools "<sf-pex-tools folder>"` |
| Take a baseline | `python -I sf-patch-day.py drift snapshot --mods mods.json -o baseline.json` |
| Check after an update | `python -I sf-patch-day.py drift check --mods mods.json --baseline baseline.json` |
| Masters in a mod manager folder | add `--plugin-dir "<folder>"` (drift, fingerprint; repeatable) |
| Probe FormIDs for in-game checks | `python -I sf-patch-day.py fingerprint "<Plugin.esm>"` |
| What changed in the Creations since the saved copy | `python -I sf-patch-day.py creations` (the first run only saves a copy) |
| Accept the changes as the new saved copy | `python -I sf-patch-day.py creations --save` |
| Name the catalog or the saved copy | add `--catalog "<ContentCatalog.txt>"` or `--saved "<file>"` (creations) |

The mods file format is in README.md ("The mods file") and `examples/mods.schema.json`. `drift init` lists the
master records the plugin overrides. With sf-pex-tools (found through `--pex-tools`, `SF_PEX_TOOLS` or a
`sf-pex-tools` folder next to sf-patch-day's folder) it also reads the mod's compiled scripts: those the plugin
names (attached, fragment and alias scripts), the `.pex` files under `Scripts\` next to the plugin, and those in
`<Mod> - <name>.ba2` archives next to it (the PC archive only, when `_xbox` or `_ps5` copies sit beside it). Run
it on the plugin in the mod's own folder: in the shared Data folder only loose scripts in the mod's own namespace,
or, without a namespace, named by its plugin or used by its own scripts (a helper it calls, a parent it extends),
count as the mod's; a helper whose functions are all native (an SFSE plugin's script) doesn't. It adds the master script functions they call (`ba2` and
`functions`) and the master quests they set stages on (`records` with `stages`); README.md "What init finds in your scripts" lists what it can't see. Without
sf-pex-tools, init prints `note: scripts not read: ...` and the author adds those by hand. A `note:` line saying a
call passes a different number of arguments than the installed master takes, or calls a function no master defines
now, means the mod was built against another game version. A `--pex-tools` folder that doesn't hold sf-pex-tools
stops init with exit 3 before anything is written. When init finds nothing it can watch by name (no overridden
master records with Editor IDs, or none whose master the plugin lists, and nothing from the scripts; the second
case prints its own note: the plugin may be damaged or unusual), init still exits 0 but writes an empty
`"masters"` and says "has nothing to watch yet"; `drift snapshot` refuses that file (exit 3) until at least one entry
is added.

## 6. Inputs, outputs, exit codes and the log

- Inputs: DLLs, zips and folders (dlls); a mods file, a baseline, the game's Data folder and optional
  `--plugin-dir` folders (drift); the game's `ContentCatalog.txt` (default `%LOCALAPPDATA%\Starfield`, for Steam
  and Game Pass) and a saved copy (default `%LOCALAPPDATA%\sf-patch-day\ContentCatalog-saved.txt`; Linux
  `$XDG_STATE_HOME/sf-patch-day`) (creations).
- Outputs: a report on stdout. The text reports of `dlls`, `drift check` and `creations`, and every failed run, end with a
  `RESULT:` line. With `--json` a finished run prints only its JSON report (`dlls --json` can do so with exit 3,
  naming unreadable files under `problems`); a run that stops before its report prints plain text (WARNING lines,
  then `RESULT: CANNOT CHECK`) on stdout, and a command-line mistake prints `RESULT: CANNOT CHECK` on stderr. Judge
  a run by its exit code; try to parse stdout as JSON, and fall back to the text when that fails. In the `dlls`
  JSON, each SFSE plugin has `framework` (`"CommonLibSF"`, `"plain SFSE"` or `"can't tell"`), `framework_why`,
  `framework_evidence`, `uses_address_library` and `address_library_evidence`, and the report has `frameworks`
  (the three counts); README.md "Which framework a plugin uses" explains them. The framework never changes the
  exit code. Also in the `dlls` JSON: per DLL `imports` and `risk`; per SFSE plugin `signature_scan_evidence`
  (`null` unless its version data says signature scans) and, for "can't tell" only, `framework_hints`; in the report
  `risk_counts` and `risk_dlls_read`. Risk evidence, the scan wording and the hints never change a verdict or exit
  code. An import shows what a DLL can call, not what it does, and "no pattern-scan signs" means no text signs were
  found, not proof: a scanner that keeps its patterns as byte arrays leaves none. `drift init` writes the mods file you
  name; `drift snapshot` writes the baseline you name. Both refuse to overwrite without `--force` and refuse to
  write inside the game folder. `creations` writes only its saved copy: on the first run, and with `--save` (a
  temporary file, then a replace); it refuses a saved copy in the game folder or the catalog's folder. Its JSON has
  `counts`, `added`, `removed`, `updated` (each with `changes`), `result` and `exit`; `Timestamp` is never
  compared, because the game rewrites it when a save loads. Nothing else is written. Never rerun `snapshot --force` in place of `check` after
  an update: that replaces the baseline the check needs.
- Exit codes: dlls 0 all work, 1 some need Address Library / may fail / need newer SFSE / SFSE missing, 2 some
  locked, or a Game Pass install with an SFSE plugin checked (Game Pass with none checked gives 0), 3 can't read or
  bad command. drift check 0 no change, 1 changed but unused, a name to check, a check skipped or a WARN about copies of a file,
  2 rebuild, 3 can't read or bad command. creations 0 no changes or a first copy saved, 1 changes, 3 can't check
  (catalog missing or broken, saved copy broken, or a refused `--saved`). init, snapshot and fingerprint: 0 done, 3
  problem.
- Log: `--verbose` writes it to stderr; `--log <file>` writes it to a file. Off unless asked.

## 7. Limits

- Read-only on the game folder. Never uploads anything; no network use at all.
- creations compares two copies of the catalog only, so it needs a copy saved before the update; it doesn't read
  the Creations' own files.
- Applies SFSE's loading rule only. A plugin that passes can still misbehave in game; "MAY FAIL" needs a test.
- Doesn't judge DLLs without SFSE version data (ASI plugins, proxy DLLs).
- Risk evidence is imports only (what a DLL can call), and "no pattern-scan signs" is not proof of fixed addresses.
- The framework comes from text left in the DLL (and a same-name PDB beside it). A stripped or packed DLL, or a
  plain-SFSE plugin with no SFSE source paths compiled in, gives "can't tell": report that as it is, never guess.
- SFSE doesn't support the Game Pass version of Starfield; dlls says so on Game Pass installs.
- drift sees only what the mods file lists. init reads the mod's scripts only with sf-pex-tools, and can't see
  quests or stage numbers worked out while the game runs, or calls made through another object's functions. A
  mod's changed copy of a master script counts as the mod's own; the mod is never listed as its own master.
