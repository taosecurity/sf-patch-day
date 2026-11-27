# sf-patch-day

sf-patch-day tells you, after a Starfield update, which of your SFSE plugins still load and what each one waits
for. For mod authors, it also says whether the update changed anything your mod relies on, so you know whether to
rebuild it. And it lists which Creations were added, removed or updated since you last looked, so you know what to
test.

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
sf-patch-day 0.3.0 dlls
Game version: 1.16.244 (read from C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe)
SFSE: 0.2.21 for this game version found (sfse_1_16_244.dll)
Address Library: versionlib-1-16-244-0.bin found (C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins)

MAY FAIL               NewModA.dll
    'NewModA' by AuthorA, plugin version 110; signature scans; no game structures
    framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: no signs
    why: version independent by signature scans
    what to do: SFSE loads it; it works only if the code it searches for is unchanged. Test it, or check its page
WORKS                  NewModB.dll
    'NewModB' by AuthorB, plugin version 1.4.17; Address Library; 1.14.70+ structure layout
    framework: CommonLibSF (11 CommonLibSF source paths, commonlib-shared, 17 RE type names); Address Library: yes (version data, versionlib file name, Address Library text)
    why: lists 1.16.244
WORKS                  NewModC.dll
    'NewModC' by AuthorC, plugin version 21.7.0; fixed addresses; no structure promise
    framework: plain SFSE (1 SFSE source path; no CommonLibSF signs); Address Library: no signs
    why: lists 1.16.244
...

Frameworks: CommonLibSF 3, plain SFSE 7, can't tell 5
RESULT: some plugins wait for an update or need testing (may fail: 3, works: 12)
```

The first three lines are the base layer that every plugin needs: the game version, SFSE for that version, and the
Address Library file for it. Then each plugin gets a verdict, a reason and, when there is something to do, what to
do. Twelve plugins work, and three find the game's code by searching for it, so they need a quick test after an
update. Each plugin's `framework` line says what it was built with (see
[Which framework a plugin uses](#which-framework-a-plugin-uses)). The last line sums it up, and the exit code (1
here) says the same thing to scripts.

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
- [creations: what a Creations update changed](#creations-what-a-creations-update-changed)
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
2. Download `sf-patch-day-0.4.0.zip` and its `.sha256` file from the
   [releases page](https://github.com/taosecurity/sf-patch-day/releases) and unzip the zip anywhere. If you want
   to check the download, run `certutil -hashfile sf-patch-day-0.4.0.zip SHA256` (on Linux,
   `sha256sum sf-patch-day-0.4.0.zip`) and compare the result with the `.sha256` file.
3. Open the unzipped folder in File Explorer, click the address bar at the top, type `cmd` and press Enter. A
   Command Prompt window opens in that folder, ready for the commands in this README.
4. Run `.\sf-patch-day.cmd --version`. It should print `sf-patch-day 0.4.0`.

`.\sf-patch-day.cmd` works in both Command Prompt and PowerShell. It only starts `python -I sf-patch-day.py` with the
options you give it, so on Linux type `python3 -I sf-patch-day.py` instead. To check the install
fully, run the tests: `python -I tests/test_sf_patch_day.py`. They end with `OK`.

**Optional, for `drift` script reading and function checks only:** download [sf-pex-tools 0.1.0](https://github.com/taosecurity/sf-pex-tools/releases)
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
- **Override:** a later plugin's copy of a record from an earlier one, which replaces it in the game.
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
.\sf-patch-day.cmd dlls "Downloads\SomePlugin.dll"       one DLL
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
sf-patch-day 0.3.0 dlls
Game version: 1.16.250 (given with --game-version)
SFSE: NOT FOUND for this game version (sfse_1_16_250.dll is missing). Every SFSE plugin waits for an SFSE update from its authors.
Address Library: versionlib-1-16-250-0.bin NOT FOUND in the folders checked (plugins that use it wait for its update)

LOCKED                 MyMod.dll
    'MyMod' by MyName, plugin version 2; Address Library; no structure promise
    framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: yes (version data, versionlib file name, Address Library text)
    why: lists only 1.16.244 (it uses Address Library but makes no structure promise, so SFSE treats it as locked)
    what to do: SFSE refuses it on this game version: turn it off until its author releases an update
NEEDS ADDRESS LIBRARY  NewModB.dll
    'NewModB' by AuthorB, plugin version 1.4.17; Address Library; 1.14.70+ structure layout
    framework: CommonLibSF (11 CommonLibSF source paths, commonlib-shared, 17 RE type names); Address Library: yes (version data, versionlib file name, Address Library text)
    why: uses Address Library; versionlib-1-16-250-0.bin was not found
    what to do: install the Address Library file for this game version when its author releases it
...

Frameworks: CommonLibSF 3, plain SFSE 7, can't tell 5
RESULT: some plugins are locked to other game versions (locked: 7, needs address library: 4, may fail: 4)
```

Options:

- `--game <folder>`: the folder holding `Starfield.exe`.
- `--game-version X.Y.Z`: judge against this version instead of the installed one.
- `--json`: print the report as JSON.
- `--verbose`, `--log <file>`: write a troubleshooting log (see [Logs](#logs)).

Paths can be DLLs, zips or folders. Folders are searched, including any zips inside them.

### Which framework a plugin uses

Most SFSE plugins are built in one of two ways: on **CommonLibSF**, a large C++ library for Starfield plugins, or on
**plain SFSE**, the plugin API that comes with SFSE and nothing more. For each SFSE plugin, `dlls` reads the DLL's
bytes (it never loads or runs the DLL) and prints a `framework` line:

```
    framework: CommonLibSF (11 CommonLibSF source paths, commonlib-shared, 17 RE type names); Address Library: yes (version data, versionlib file name, Address Library text)
    framework: plain SFSE (1 SFSE source path; no CommonLibSF signs); Address Library: no signs
    framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: no signs
```

The brackets give the evidence that decided it:

- **CommonLibSF** when the DLL holds at least one CommonLibSF source path (such as `commonlibsf\src\SFSE\...`), the
  text `commonlib-shared` (CommonLibSF's shared part), or at least 3 names of CommonLibSF's game classes (its `RE`,
  `REL` and `REX` namespaces).
- **plain SFSE** when there is no CommonLibSF sign and the DLL holds at least one of SFSE's own source paths
  (`sfse_common\...` or `sfse\sfse\...`).
- **can't tell** otherwise. sf-patch-day doesn't guess.

The word "CommonLibSF" on its own is not a sign, because other libraries name CommonLibSF's file formats too. If a
PDB (the debug symbols file) with the same name sits next to the DLL, in the same folder or the same zip folder, it
is read the same way and its signs count too: `(15 CommonLibSF source paths in the DLL, 624 in its PDB, ...)`. The
3-name test for game classes applies to the DLL and the PDB one at a time, because both files often name the same
class.
Many plugins ship without one, and a PDB bigger than 1 GB (512 MB inside a zip) is skipped.

**Address Library** says `yes` when the version data says the plugin uses it, when the DLL names a `versionlib`
file, or when it holds the text "Address Library". `no signs` means none of those were found, not that the plugin
surely doesn't use it.

The framework is information only: it doesn't change the verdict or the exit code. The last lines of the report
count the plugins (`Frameworks: CommonLibSF 3, plain SFSE 7, can't tell 5`).

With `--json`, each SFSE plugin also gets these keys (helper DLLs and unreadable files don't):

- `framework`: `"CommonLibSF"`, `"plain SFSE"` or `"can't tell"`;
- `framework_why`: the text in the brackets;
- `framework_evidence`: `commonlibsf_paths`, `commonlib_shared`, `re_types` and `sfse_paths` (the DLL's counts),
  `exports` (which of `SFSEPlugin_Load`, `SFSEPlugin_Version` and `SFSEPlugin_Preload` it exports), `pdb` (the
  PDB read, or `null`) and `pdb_counts` (the PDB's four counts, or `null`);
- `uses_address_library` (`true` or `false`) and `address_library_evidence` (the list in the brackets).

The report also gets `frameworks`, the three counts.

### What else `dlls` prints about each DLL

Three more lines help you judge a plugin by hand. None of them changes a verdict or the exit code.

**Risk evidence.** Every DLL `dlls` can read gets a line that lists which Windows functions it imports from four
groups: network (anything imported from a networking DLL such as `ws2_32.dll` or `winhttp.dll`), process launch
(`CreateProcessW`, `ShellExecuteW` and the like), runtime DLL loading (`LoadLibraryW` with `GetProcAddress`) and code
patching (`VirtualProtect`, `WriteProcessMemory` and the like):

```
    risk evidence (not a verdict): network (ws2_32.dll: WSAStartup, getaddrinfo, connect); process launch (CreateProcessW); runtime DLL loading (GetProcAddress) [the C runtime imports these itself]; code patching (VirtualProtect, FlushInstructionCache) [most SFSE plugins have this (SFSE's hooks need it)]
    risk evidence (not a verdict): none of the four kinds in its imports
```

An import shows what a DLL **can** call, not what it does. Nearly every SFSE plugin patches code, because SFSE's hooks
need `VirtualProtect`, so those names carry a note instead of looking like a warning. Programs built with the static
C runtime also import `LoadLibraryExW` and `GetProcAddress` for themselves, and `ShellExecute` also opens web pages
and folders. Only function names from sf-patch-day's own table are printed. The report ends with a summary line such
as `Risk evidence: network 1, process launch 1, runtime DLL loading 3, code patching 3 (of 3 DLLs read)`. A damaged
import table is noted and skipped, never fatal. An import table that isn't fully read (damaged entries, more than
20,000 imported functions, more than 4,096 imported DLLs in one table, or a file with more than 96 sections, whose
imports aren't read at all) says so on its line, as `(import table not fully read: ...)`, and the summary adds how many
DLLs that was.

**Signature scans, only with evidence.** A DLL's version data can claim that it finds the game's code by signature
scanning. `dlls` now looks for signs of a scanner in the DLL: byte-pattern text with `??` wildcards, scanner words such
as "find pattern", or a scanner class name. With signs the plugin reads `signature scans`. Without them it reads
`says signature scans, but no pattern-scan signs found`, and a plugin that SFSE treats as version independent gets the
MAY FAIL reason "version independent by its version data's signature-scan claim, but no pattern-scan signs were found
(not proof: a scanner can keep its patterns as byte arrays), so it may use fixed addresses and refuse to load or crash
on this version". "No pattern-scan signs" means no text signs were
found. It is not proof: a scanner that stores its patterns as byte arrays leaves none. The verdict is still SFSE's
rule and is not changed.

**Framework hints.** For a DLL whose framework is "can't tell", a `framework hints` line lists what could still place
it: well-known libraries named in its type information (`spdlog`, `fmt`, `toml`, `DKUtil` and a few more), SFSE's own
plugin API types (`SFSETaskInterface` and the other four), and quoted text from its own Address Library reader or game
version check (cut to 80 characters, with unusual characters shown as `\xNN`). A library name is a hint, not proof of
a framework: other plugins use `spdlog` and `fmt` too. The `Frameworks:` counts stay as they are. With nothing found,
the line reads `framework hints: none (a stripped or packed DLL leaves none)`.

With `--json`, each readable DLL also gets `imports` (`dlls`, `count`, `delayed`, `problem`) and `risk` (`network`,
`process_launch`, `dll_loading` and `code_patching`, each with its `imports` and `note`; `network` also has `dlls` and
`unlisted`, the count of other functions per networking DLL, and `code_patching` has `other_process` and `text`); each SFSE plugin gets
`signature_scan_evidence` (`null` unless its version data claims signature scans, `[]` when it does but nothing was
found); a "can't tell" plugin also gets `framework_hints`. The report gets `risk_counts` (the four counts) and
`risk_dlls_read`.

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
   rebuild. With sf-pex-tools installed, it also reads your mod's compiled scripts and adds the master script
   functions they call and the master quest stages they set (see [What init finds in your scripts](#what-init-finds-in-your-scripts)).
   Without sf-pex-tools it says so, and you add those by hand (see [The mods file](#the-mods-file)).

   When init finds nothing it can watch by name (no overridden master records with Editor IDs, or none whose
   master the plugin lists, which it notes as possibly damaged or unusual, and nothing from the scripts), it writes
   a mods file with nothing in it yet and says so: add at least one entry before you run `snapshot`.
2. `snapshot` records facts about each listed record: its FormID, type, a hash of its contents, its quest stages
   and condition count, and the argument count of each listed script function. Take it when your mod is built and
   working. Keep `mods.json` and `baseline.json` with your mod's source.
3. `check` compares the installed masters with the baseline.

A real `init` run on a script-only mod that changes no master records (mod name changed), with sf-pex-tools in a
folder next to sf-patch-day:

```
> .\sf-patch-day.cmd drift init ..\MyMod\MyMod.esm -o mods.json
wrote mods.json: 0 overridden record(s), 40 master script function(s) your scripts call and 15 master quest(s) they set stages on, in 1 master(s)
  read 4 of your mod's own script(s) with sf-pex-tools 0.1.0 (C:\temp\patchday-example\sf-pex-tools)
  Starfield.esm: 15 record(s), 15 with quest stages, 40 function(s) in 15 script(s) from Starfield - Misc.ba2
Next: check the file, add anything else your mod relies on, then run drift snapshot (with sf-pex-tools, for the function checks).
```

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
- `--pex-tools <folder>`: where sf-pex-tools is. `init` reads your scripts with it; `snapshot` and `check` compare
  the listed functions with it. Without this option, sf-patch-day looks in `SF_PEX_TOOLS` and then in a
  `sf-pex-tools` folder next to its own.
- `--json`: print the `check` report as JSON.
- `--force`: let `init` and `snapshot` overwrite their files. Take a new baseline only after you rebuild your mod,
  never instead of `check`.
- `--verbose`, `--log <file>`: write a troubleshooting log.

Names are matched the way the game matches them: Editor IDs, script paths and function names ignore case, and
record types are read in upper case. A record, stage, script or function that is missing now and was also missing
when you took the baseline is a `NOTE` (check the name), not a rebuild. `snapshot` already names the records it
can't find on its summary line, and `check` compares records again only after the master changed, so check the
snapshot's line for typos.

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

### What init finds in your scripts

With sf-pex-tools, `init` reads the scripts your plugin names (the scripts attached to its records, and the
fragment and alias scripts of its quests, dialogue, scenes, packages, perks and terminal menus) and the compiled
scripts (`.pex`) your mod ships: loose ones under `Scripts\` next to the plugin, and the ones in its own archives
(`MyMod - Main.ba2` and other `MyMod - <name>.ba2` files next to it). When a Creations build folder holds both
`MyMod - Main.ba2` and `MyMod - Main_xbox.ba2` (or `_ps5`), only the PC archive is read. The masters' scripts come
from their own archives (such as `Starfield - Misc.ba2`) in the Data folder and `--plugin-dir` folders.

Which copy of a script counts follows the game's rule: a loose file beats every archive, and a later archive beats
an earlier one. So when your mod ships its own changed copy of a master's script (in its archive, or loose), that
copy is your mod's own script, not the master's, and your mod is never listed as its own master.

Where your plugin sits matters for loose scripts:

- In its own folder (your source folder, or a mod manager's folder for this mod), every loose `.pex` under
  `Scripts\` is your mod's.
- In the game's Data folder (or a `--plugin-dir` folder), `Data\Scripts` holds every mod's loose scripts. There a
  loose script counts as yours when its namespace (the part before the first `:`, such as `MyMod` in
  `MyMod:QuestScript`) is one your plugin's scripts or your archive use and no master uses, or, for a script with
  no namespace or a `Fragments:` script, when your plugin names it or one of your mod's own scripts uses it (as a
  helper it calls with `callstatic` or a parent it extends; a type it only declares isn't enough). A `note:` line
  lists the scripts taken in that way.
- There, a helper whose functions are all native (the script of an SFSE plugin, whose code is in its DLL) is left
  out: it's another mod's, and there's no code in it to read.
- In the Data folder, a master installed loose is recognized by the scripts its own records name. A loose copy of
  a master script there could be any mod's, so init reads the master's archive copy and says so in a `note:` line.
- Settled limits in the shared Data folder: a bare helper taken in through `callstatic` or a parent can bring in
  its own `callstatic` targets and parents too, and a bare script the mod only holds in a property or variable
  isn't read. Run init on the plugin in your mod's own folder to avoid both.

From the code it adds:

- Each master script function your scripts call, under the script that defines it. A call to a function a script
  inherits is listed under the parent that defines it, such as `scripts/scriptobject.pex` for `StartTimer`. The
  master's archive goes in `ba2`. If a call passes a different number of arguments than the installed master's
  function takes, or calls a function no master script defines now, init says so in a `note:` line: your mod was
  built against another version of the game, so rebuild it.
- Each master quest your scripts call `SetStage` or `SetCurrentStageID` on, with the stage numbers, when the quest
  is a script property your plugin fills (or the quest itself, when your plugin attaches the script, or a quest
  fragment script, to an override of a master quest). A stage number counts when it is written in the script or
  comes from an Int property your plugin fills. Quests and stages handed down through your script's own functions,
  such as `Step(MyQuest, 100)` calling `akQuest.SetStage(aiStage)`, are followed too. A quest your plugin overrides
  keeps its `copied: true` record and gets the stages added.
- A master's own fragment and alias scripts, kept in your plugin's copy of a master record, are the master's and
  aren't read for stages. So is a master's attached script that the master's copy of the record already has, with
  the same values for the quest and stage properties it reads. A master script your plugin adds to the record, one
  whose quest or stage property your plugin changes, or one your mod ships its own copy of, is read as yours (and so
  is one on a record whose master copy can't be read or whose master isn't installed; the log says which).

What it can't see: a quest or stage number worked out while the game runs (a variable, a calculation, a number
above 65535, a quest found with `Game.GetForm` or `GetOwningQuest()`), and calls made through another object's own
functions. Such a quest is left out, and a quest with an unknown stage says so in its `why` text.

A loose script in the Data folder that doesn't match the rules above is left out; to have init read all of your
loose scripts, run it on the plugin in your own folder. Script properties of type Var (which the Creation Kit
can't fill) are skipped.

A mod with more than 5,000 scripts of its own is read up to that limit, with a `note:` line that says at least how
many more weren't read (the scripts those reference aren't found, so there may be more). A script that wasn't read
still counts as your mod's for the records it's attached to.

When a record's fragment scripts can be read two ways that both fit (Mutagen and xEdit lay out an empty fragment
script name differently), init uses the usual layout for that record type and says so in a `note:` line per record
type, with up to 20 FormIDs (the `--verbose` log lists every one).

Check the file and add anything else by hand. The same mod and the same game files always give the same file.

## creations: what a Creations update changed

The game keeps a list of the Creations you have installed in `ContentCatalog.txt`: each one's title, version and
files. `creations` compares that list with a copy it saved on an earlier run, and lists the Creations that were
added, removed or updated since then. Run it after a game update or a visit to the Creations menu, before you test.

```
.\sf-patch-day.cmd creations
```

The first run saves a copy of the catalog and reports nothing. Run it again after the next update to see what
changed. This run uses two made-up catalogs (every name in it is made up):

```
> .\sf-patch-day.cmd creations
Creations catalog: C:\Users\Player\AppData\Local\Starfield\ContentCatalog.txt (4 Creations)
Compared with: C:\Users\Player\AppData\Local\sf-patch-day\ContentCatalog-saved.txt (saved 2026-11-20 14:03, 4 Creations)
ADDED   Example Outfits (TM_55555555-5555-5555-5555-555555555555) version 1.2.0, files: ExampleOutfits.esm, ExampleOutfits - Main.ba2
REMOVED Old Example Patch (TM_22222222-2222-2222-2222-222222222222) version 0.9.0, files: OldExamplePatch.esm
UPDATED Example Ships (TM_11111111-1111-1111-1111-111111111111): version 1.0.0 -> 1.1.0; files added: ExampleShips - Textures.ba2
Unchanged: 1. Timestamp-only changes (the game rewrites these when you load a save): 1, not shown.
RESULT: CHANGES: 1 added, 1 removed, 1 updated. Test these Creations before you play; run with --save to make this the new saved copy.
```

- **Where it looks:** `%LOCALAPPDATA%\Starfield\ContentCatalog.txt`, for Steam and Game Pass alike. On Linux
  (Proton), the same folder inside each Steam library's `compatdata/1716740` prefix. Give another file with
  `--catalog <file>`. The game's file is only read.
- **The saved copy:** `%LOCALAPPDATA%\sf-patch-day\ContentCatalog-saved.txt` (on Linux,
  `$XDG_STATE_HOME/sf-patch-day`, by default `~/.local/state/sf-patch-day`). It is an exact copy of the game's file,
  so you can open it. Give another file with `--saved <file>`. sf-patch-day refuses a saved copy in the game folder
  or in the folder that holds the catalog.
- **The saved copy stays as it is** until you add `--save`, so running the command twice shows the same report.
  When you have looked at the changes, run it with `--save` to make the current catalog the new starting point.
- **What counts as a change:** a Creation's version, title, files (compared without regard to upper or lower
  case), size, or whether it is achievement-friendly, and any field a later game version adds. The version is
  shown without the date number the game puts in front of it (`1757190740.1.0.0` shows as `1.0.0`); `--json` keeps
  it whole. When only that date number changed, the line says `re-uploaded (same version 1.0.0)`. The `Timestamp` field is never compared, because the game rewrites it when a save loads. Those entries
  are only counted, and `--verbose` lists their IDs.
- **JSON:** `--json` prints `counts`, `added`, `removed`, `updated` (each with its `changes`), `result` and `exit`.
- **Exit codes:** 0 no changes (or a first copy saved), 1 changes, 3 can't check (the catalog is missing or broken,
  or the saved copy is broken; the message says how to fix it).

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

Vortex keeps mods in its staging folder and deploys them into Data. MO2 never copies them there. It keeps them in its own
folders and shows them only to programs it starts:

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

`creations` returns 0 when nothing changed or it saved a first copy, 1 when Creations were added, removed or
updated, and 3 when it can't check. `drift init`, `drift snapshot` and `fingerprint` return 0 on success and 3 on a
problem. Scripts should rely on the exit code. The rest of this section is for people who read the output from a
script:

- The text reports of `dlls`, `drift check` and `creations`, and every failed run, end with a `RESULT:` line.
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
- Risk evidence lists imports: it shows what a DLL can call, not what it does, and a DLL can load code at run time without importing anything unusual.
- "No pattern-scan signs" means no text signs were found, not proof: a scanner that stores its patterns as byte arrays leaves none.
- The framework line reads text left in the DLL. A stripped, packed or obfuscated DLL gives "can't tell", and so
  does a plain-SFSE plugin that compiled none of SFSE's source paths in. The counts are evidence, not a license or
  build audit.
- `drift` sees only what the mods file lists. `init` fills it from your overrides and, with sf-pex-tools, from your
  compiled scripts, but it can't see quests or stage numbers worked out while the game runs (see
  [What init finds in your scripts](#what-init-finds-in-your-scripts)).
- `creations` can only show what changed between two copies of the catalog: it needs a copy saved before the
  update. It reads only the catalog, not the Creations' own files.
- It doesn't download updates, and it doesn't turn plugins off for you.

## Found a mistake?

Open an issue: https://github.com/taosecurity/sf-patch-day/issues. Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## Credits and license

sf-patch-day was made by Richard Bejtlich. It applies the plugin loading rule of
[SFSE](https://sfse.silverlock.org), the Starfield Script Extender, and reads the Address Library files that SFSE
plugin authors use; it ships neither. Reading scripts and checking script functions use
[sf-pex-tools](https://github.com/taosecurity/sf-pex-tools) when it's installed. Starfield belongs to Bethesda
Softworks, and sf-patch-day ships no game files.

sf-patch-day is released under the MIT license (see [LICENSE](LICENSE)).
