# Changelog

## 0.1.0 (not yet released)

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
