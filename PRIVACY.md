# Privacy

sf-patch-day runs on your own computer, offline. It collects no data and sends nothing anywhere.

## What it does not do

- It makes no network connections.
- It has no telemetry, analytics, crash reporting or update checks.
- It starts no other programs. It never loads or runs the DLLs it checks: it only reads their bytes (headers,
  version data, export names, and the text it counts to name each plugin's framework).
- It loads sf-pex-tools' Python files only when a mods file lists script functions, from the folder you name with
  `--pex-tools`, the `SF_PEX_TOOLS` environment variable, or a `sf-pex-tools` folder next to its own folder.

## What it reads

- the DLLs, zips, folders, mods files and baselines you name on the command line, and a PDB file with the same name
  next to a DLL (in the same folder or the same zip folder), when there is one;
- the game folder: `Starfield.exe`'s and SFSE's version data, the `Data\SFSE\Plugins` folder, and the master
  plugins and archives your mods file names;
- to find the game when you don't give `--game` or `--data`: Steam's location from the Windows registry
  (`SteamPath`, `InstallPath`), Steam's `libraryfolders.vdf`, and whether `<drive>:\XboxGames\Starfield\Content`
  exists on each drive.

## What it writes

- `drift init` writes the mods file you name; `drift snapshot` writes the baseline you name. Both refuse to write
  inside the game folder.
- `--log <file>` writes a troubleshooting log to that file.

Nothing else.

## What the output contains

The report shows the paths of the files it read, and each plugin's name and author as its DLL states them. A log
also shows the game folder it found, which includes your Steam library path. Read a log before you post it.

## Downloading it

Downloading sf-patch-day from GitHub is covered by GitHub's own
[privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement). Its
author receives only the public download counts GitHub shows.

## Questions

Open an issue at https://github.com/taosecurity/sf-patch-day/issues.
