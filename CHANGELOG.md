# Changelog

## 0.5.3 (2026-11-27)

### Fixed

A DLL with a huge number of sections (a made-up one with 65,535 sections and 65,536 export names took minutes) no longer stalls `dlls`. The export readers now refuse a file with more than 96 sections, as the import reader already did, and the DLL is listed as unreadable with that reason.

`dlls` with no paths no longer ends with `RESULT: some files couldn't be read` and exit 3 when the game has no `Data\SFSE\Plugins` folder, which is always the case on Game Pass. It says that no SFSE plugins are installed and exits 0. Two cases still give another code, as the README exit-code table says: on Steam, a missing SFSE for this game version gives 1, and on Game Pass, a checked SFSE plugin gives 2. A path you give that doesn't exist, or a plugins folder that this account can't read, still gives exit 3. On Linux and Proton, where folder names are case-sensitive but the game's aren't, a plugins folder spelled in other case (`Data/sfse/plugins`) is found and checked, as the game would load it.

Smaller fixes: `fingerprint <path>` now also searches the game's Data folder for the masters of a plugin outside Data, so a light or medium master isn't counted as full, and prints a `WARNING` line when a master isn't found. `drift check` reads the baseline before it scans the masters, so a mistyped `--baseline` is reported at once, and a hand-damaged master entry in a baseline is a `CANNOT CHECK` that names the file instead of an unexpected error. A game folder is Game Pass only when it holds `appxmanifest.xml`, so a Steam library inside a folder named XboxGames is no longer treated as Game Pass.

### Example

This run checks a made-up Game Pass install that has no SFSE plugins folder (0.5.2 ended it with `RESULT: some files couldn't be read` and exit 3):

    > .\sf-patch-day.cmd dlls --game D:\Games\Starfield --game-version 1.16.244
    sf-patch-day 0.5.3 dlls
    No SFSE plugins folder (D:\Games\Starfield\Data\SFSE\Plugins): no SFSE plugins are installed.
    Game version: 1.16.244 (given with --game-version)
    SFSE: this is a Game Pass install, and SFSE doesn't support Game Pass, so SFSE plugins don't load here and no SFSE update will change that
    Address Library: versionlib-1-16-244-0.bin NOT FOUND in the folders checked (plugins that use it wait for its update)

    No DLLs to check.

    RESULT: everything checked loads (no DLLs)

## 0.5.2 (2026-11-27)

### What's new

`creations` now shows the invisible format and line-separator characters in Creation titles and file lists as `\uNNNN`, the same way the `dlls` report does since 0.5.1. Those names come from other authors, and a right-to-left override (U+202E) in a title could make the line read differently from what it holds. Before, only control characters were escaped there; the head lines that name the catalog and the saved copy are escaped now too. The `drift` report lines (the `drift init` master lines and notes, the snapshot summary, its "not found" lines and every `drift check` finding), the `fingerprint` line and the `WARNING:` lines about copies of a file that differ only in case get the same escaping, because they hold names from your mods file, your plugins and your folders. The `--json` output was already safe and doesn't change.

`dlls` also finds more signs of a pattern scanner in a plugin whose version data claims signature scans. Pattern text with only one A-F byte and no wildcard (such as `40 53 48 83 EC 20`, a common function start) now counts, and so does the text "find pattern" (as in a "failed to find pattern" message). Tables of digit-only numbers still don't count. On the 50 real SFSE plugins we checked, no label, verdict or exit code changed. On other plugins one can: a plugin that claims signature scans and now shows one of these signs no longer gets the MAY FAIL reason for a claim with no pattern-scan signs.

### Example

This run compares two made-up catalogs, where the new Creation's title holds a right-to-left override (output shortened to the changed lines):

    > .\sf-patch-day.cmd creations
    ADDED   Example Tools \u202edexiF (TM_22222222-2222-2222-2222-222222222222) version 1.2.0, files: ExampleTools.esm
    RESULT: CHANGES: 1 added, 0 removed, 0 updated. Test these Creations before you play; run with --save to make this the new saved copy.

Before 0.5.2 the override itself was printed, so a terminal that honors it showed the rest of the line reversed (`dexiF` read as `Fixed`).

## 0.5.1 (2026-11-27)

### Fixed

The `dlls` text report now shows every control character in text it takes from a DLL, a zip member name or a file name as `\xNN` (or `\uNNNN`, or `\UNNNNNNNN` above U+FFFF), including the plugin's author, which 0.5.0 printed as it was. A hostile DLL could put an ESC sequence or a newline in the author field of its version data and so rewrite the terminal or fake a report line. The same escape now covers every other line of the text report (file names, zip member names, reasons, notes) and every line of the troubleshooting log (`--verbose`, `--log`), which also printed file and zip member names as they were, and the `RESULT: CANNOT CHECK` line of a run that stops (with any command), which can quote a file, zip member or BA2 member name. The invisible format characters (such as the zero-width joiner U+200D and the soft hyphen U+00AD) are shown the same way. A file name with a broken character (a lone UTF-16 surrogate) is shown as `\uNNNN` and no longer stops a run with `--log` with an unexpected error. Other text prints exactly as before, and the JSON output was already safe. Verdicts and exit codes don't change.

### Example

This run uses one made-up DLL whose author field holds an escape code and a line break that would otherwise have printed a fake `RESULT:` line (every name in it is made up; output shortened to the DLL's own lines):

    > .\sf-patch-day.cmd dlls C:\Example\Plugins --game-version 1.16.244
    WORKS                  ExampleHostile.dll
        'ExampleHostile' by Mallory\x1b[2J\x0aRESULT: everything checked loads, plugin version 16.0.0; fixed addresses; no structure promise
        why: lists 1.16.244

## 0.5.0 (2026-11-27)

### What's new

sf-patch-day 0.5.0 makes `dlls` say more about each SFSE plugin DLL, so you can judge one without a separate strings scan. Each DLL it can read gets a "risk evidence" line that lists which network, process-launch, runtime-DLL-loading and code-patching functions it imports (evidence, not a verdict: an import shows what a DLL can call, not what it does). A plugin whose version data claims signature scans now reads "signature scans" only when the DLL shows signs of a pattern scanner; otherwise it reads "says signature scans, but no pattern-scan signs found" (no signs is not proof, because a scanner can keep its patterns as byte arrays). A plugin whose framework is "can't tell" gets a "framework hints" line with the libraries and SFSE types it names and its own Address Library and game version text. Verdicts and exit codes don't change.

### Example

This run uses three made-up DLLs (every name in it is made up):

    > .\sf-patch-day.cmd dlls C:\Example\Plugins --game-version 1.16.244
    WORKS                  ExampleClaim.dll
        'ExampleClaim' by AuthorA, plugin version 2; says signature scans, but no pattern-scan signs found; no structure promise
        framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: no signs
        framework hints: none (a stripped or packed DLL leaves none)
        risk evidence (not a verdict): runtime DLL loading (GetProcAddress) [the C runtime imports these itself]; code patching (VirtualProtect, FlushInstructionCache) [most SFSE plugins have this (SFSE's hooks need it)]
        why: lists 1.16.244
    WORKS                  ExampleHooks.dll
        'ExampleHooks' by AuthorC, plugin version 1; fixed addresses; no structure promise
        framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: no signs
        framework hints: libraries spdlog (CommonLibSF plugins use spdlog and fmt, but so do others); SFSE plugin API types (SFSETaskInterface); its own game version check text: "Only game version 1.16.244 is supported"
        risk evidence (not a verdict): runtime DLL loading (GetProcAddress) [the C runtime imports these itself]; code patching (VirtualProtect, FlushInstructionCache) [most SFSE plugins have this (SFSE's hooks need it)]
        why: lists 1.16.244
    WORKS                  ExampleScanner.dll
        'ExampleScanner' by AuthorB, plugin version 3; signature scans; no structure promise
        framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: no signs
        framework hints: none (a stripped or packed DLL leaves none)
        risk evidence (not a verdict): network (ws2_32.dll: WSAStartup, getaddrinfo, connect); process launch (CreateProcessW); runtime DLL loading (GetProcAddress) [the C runtime imports these itself]; code patching (VirtualProtect, FlushInstructionCache) [most SFSE plugins have this (SFSE's hooks need it)]
        why: lists 1.16.244

    Frameworks: CommonLibSF 0, plain SFSE 0, can't tell 3
    Risk evidence: network 1, process launch 1, runtime DLL loading 3, code patching 3 (of 3 DLLs read)
    RESULT: everything checked loads (works: 3)

On a real run over 41 DLLs (the 15 plugins in a Steam install's SFSE folder plus 26 DLLs from other mods), 7 DLLs read "says signature scans, but no pattern-scan signs found", and the summary read `Risk evidence: network 7, process launch 7, runtime DLL loading 32, code patching 29 (of 41 DLLs read)`.

### Changes

- `dlls` prints a risk evidence line for each readable DLL and a `Risk evidence:` summary line; JSON `imports`, `risk`, `risk_counts` and `risk_dlls_read`. A DLL whose import table isn't fully read (damaged entries, more than 20,000 imported functions, more than 4,096 imported DLLs in one table, or more than 96 sections) says so on its line and in the summary.
- `dlls` prints "signature scans" only with signs of a pattern scanner, and otherwise "says signature scans, but no pattern-scan signs found" (the MAY FAIL reason and its what to do line are reworded); JSON `signature_scan_evidence`.
- `dlls` prints a `framework hints` line for "can't tell" plugins; JSON `framework_hints`. Text quoted from a DLL shows control characters, the double quote and the backslash as `\xNN`.
- README.md "What else `dlls` prints about each DLL" explains all three.

## 0.4.0 (2026-11-25)

### What's new

sf-patch-day 0.4.0 adds the `creations` command, which lists the Creations that were added, removed or updated since you last looked. The game keeps the list of your installed Creations in `ContentCatalog.txt`. The first run saves a copy of that file, and each later run compares the game's file with the copy and names every Creation whose version, title, files, size or achievement setting changed. Run it after a game update or a visit to the Creations menu, so you know which Creations to test. The game's file is only read. The other commands haven't changed.

### Example

This run uses two made-up catalogs (every name in it is made up):

    > .\sf-patch-day.cmd creations
    Creations catalog: C:\Users\Player\AppData\Local\Starfield\ContentCatalog.txt (4 Creations)
    Compared with: C:\Users\Player\AppData\Local\sf-patch-day\ContentCatalog-saved.txt (saved 2026-11-20 14:03, 4 Creations)
    ADDED   Example Outfits (TM_55555555-5555-5555-5555-555555555555) version 1.2.0, files: ExampleOutfits.esm, ExampleOutfits - Main.ba2
    REMOVED Old Example Patch (TM_22222222-2222-2222-2222-222222222222) version 0.9.0, files: OldExamplePatch.esm
    UPDATED Example Ships (TM_11111111-1111-1111-1111-111111111111): version 1.0.0 -> 1.1.0; files added: ExampleShips - Textures.ba2
    Unchanged: 1. Timestamp-only changes (the game rewrites these when you load a save): 1, not shown.
    RESULT: CHANGES: 1 added, 1 removed, 1 updated. Test these Creations before you play; run with --save to make this the new saved copy.

On a real Steam catalog of 58 Creations, with one entry edited and one removed from the saved copy, the result line read `CHANGES: 1 added, 0 removed, 1 updated`, and 28 entries whose only change was the game's `Timestamp` were counted but not listed.

### Changes

- New command `creations [--catalog FILE] [--saved FILE] [--save] [--json]`. It reads `%LOCALAPPDATA%\Starfield\ContentCatalog.txt` (Steam and Game Pass; on Linux, the Proton prefix of each Steam library) and keeps its copy in `%LOCALAPPDATA%\sf-patch-day\ContentCatalog-saved.txt` (on Linux, `$XDG_STATE_HOME/sf-patch-day`). README.md, "creations: what a Creations update changed", explains it.
- The saved copy changes only on the first run and with `--save`. A saved copy in the game folder or the catalog's folder is refused.
- `Timestamp` is never compared, because the game rewrites it when a save loads.
- Exit codes: 0 no changes or a first copy saved, 1 changes, 3 can't check.
- A catalog with a number too long or too large to read (or NaN) is refused as not a catalog. Control characters in a Creation's title, files or other fields are shown as `\xNN` in the report, so a title can't add a line or send terminal codes.

## 0.3.0 (2026-11-24)

### What's new

sf-patch-day 0.3.0 says which framework each SFSE plugin was built with: CommonLibSF, plain SFSE (SFSE's own plugin API without CommonLibSF), or "can't tell". It also says whether the plugin shows signs of using Address Library. Each answer comes with the evidence that decided it. sf-patch-day reads the DLL's bytes for this, and a same-name PDB beside it when there is one. It never loads or runs the DLL, and it says "can't tell" rather than guess. The verdicts and exit codes haven't changed.

### Example

This is a real run on one installed plugin (the mod and author names changed):

    > .\sf-patch-day.cmd dlls "C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins\NewModB.dll"
    sf-patch-day 0.3.0 dlls
    Game version: 1.16.244 (read from C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe)
    SFSE: 0.2.21 for this game version found (sfse_1_16_244.dll)
    Address Library: versionlib-1-16-244-0.bin found (C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins)

    WORKS                  NewModB.dll
        'NewModB' by AuthorB, plugin version 1.4.17; Address Library; 1.14.70+ structure layout
        framework: CommonLibSF (11 CommonLibSF source paths, commonlib-shared, 17 RE type names); Address Library: yes (version data, versionlib file name, Address Library text)
        why: lists 1.16.244

    Frameworks: CommonLibSF 1, plain SFSE 0, can't tell 0
    RESULT: everything checked loads (works: 1)

On a Steam install with 15 SFSE plugins, the last lines read `Frameworks: CommonLibSF 3, plain SFSE 7, can't tell 5`.

### Changes

- `dlls` prints a `framework:` line for each SFSE plugin and a `Frameworks:` count before the `RESULT:` line. README.md, "Which framework a plugin uses", explains the signs it counts and the rule it applies.
- `dlls --json` adds the keys `framework`, `framework_why`, `framework_evidence`, `uses_address_library` and `address_library_evidence` to each SFSE plugin, and `frameworks` to the report. No key was renamed or removed.
- A PDB with the same name as the DLL, in the same folder or the same zip folder, is read too. A PDB bigger than 1 GB (512 MB inside a zip) is skipped.
- The README shows how to check one DLL (`dlls <file.dll>`).
- The README says that Vortex deploys mods into Data and Mod Organizer 2 never does.

## 0.2.2 (2026-11-23)

### What's new

sf-patch-day 0.2.2 makes the `drift init` log clearer when a master plugin isn't installed. The log now says which master is missing, where it used to say that the master's copy "can't be read". The result is the same as in 0.2.1: the script's quest stages are credited to your mod. The mods file and the command line haven't changed.

### Example

This is the tool's real output on a made-up test mod whose master list names a plugin, Later.esm, that isn't in the Data folder. The last line comes from the log file written with `--log`:

    > .\sf-patch-day.cmd drift init ..\MyMod\MyMod.esm -o mods.json --data ..\Data --pex-tools ..\sf-pex-tools --log init.log
    wrote mods.json: 1 overridden record(s), 0 master script function(s) your scripts call and 1 master quest(s) they set stages on, in 1 master(s)
      read 0 of your mod's own script(s) with sf-pex-tools 0.1.0 (..\sf-pex-tools)
      TestMaster.esm: 1 record(s), 1 with quest stages
    note: masters not found, so FE/FD record numbers may be misread: Later.esm (give --data or --plugin-dir)
    Next: check the file, add anything else your mod relies on, then run drift snapshot (with sf-pex-tools, for the function checks).

    init.log: TM:Starter on QUST 01000800: Later.esm isn't installed and might hold the last copy; its stages are credited to MyMod.esm

### Changes

- When a master that isn't installed is the reason init can't compare a master's copy of a record, the log line names that master ("Later.esm isn't installed and might hold the last copy"). A master that is installed but whose copy can't be read still gets "the master's copy can't be read".
- The CI workflow of the public repository now uses the current majors of its actions (checkout 7, setup-python 7, upload-artifact 7, download-artifact 8), each pinned by commit, so the run has no Node.js 20 warning.

## 0.2.1 (2026-11-22)

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
- When a master that could hold that record isn't installed or can't be read, the script still counts as yours, as in 0.2.0, since init can't tell whose it is.
- A script of your mod that wasn't read because of the safety limit (5,000 scripts) still counts as yours, so its quest stages on an overridden master record are kept.
- The safety limit's `note:` line counts only your mod's own unread scripts and says "at least". Before, it could count other mods' loose scripts. Past the limit, a loose script with no namespace that only your scripts' code reaches is counted only when it has code of its own (not all native).
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
