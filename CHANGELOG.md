# Changelog

## 0.1.1 (not yet released)

Small fixes to the case-insensitive file name lookup added in 0.1.0 (used on Linux and Proton, where file names
are case-sensitive but the game's aren't).

- When several files in a folder differ only in case, a WARNING names them and says the game may load another copy
  than the one checked. It shows in the normal output (once per file), and `drift check` counts it as a NOTE
  (exit 1).
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
