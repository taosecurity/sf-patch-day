# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""Where the game is on a player's PC.

Search order for the game folder (the one holding Starfield.exe), used when --game isn't given:
  1. Steam: the Steam folder from the registry, %ProgramFiles(x86)%\\Steam, and every library listed in each one's
     steamapps\\libraryfolders.vdf, as <library>\\steamapps\\common\\Starfield
  2. Game Pass: <drive>:\\XboxGames\\Starfield\\Content on every drive
On Linux (Proton) the usual Steam folders under the home folder are searched instead.

Mod managers: MO2 and Vortex keep mods outside the game folder until they deploy them. Give their folders as
paths (dlls) or with --plugin-dir (drift); see the README.
"""
import os
import re
import string
import sys

from . import log


def _steam_roots(env):
    roots = []
    if sys.platform == "win32":
        try:
            import winreg
            for hive, key, value in ((winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
                                     (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath")):
                try:
                    with winreg.OpenKey(hive, key) as k:
                        roots.append(os.path.normpath(winreg.QueryValueEx(k, value)[0]))
                except OSError:
                    pass
        except ImportError:
            pass
        pf86 = env.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        roots.append(os.path.join(pf86, "Steam"))
    else:
        home = os.path.expanduser("~")
        roots += [os.path.join(home, ".steam", "steam"), os.path.join(home, ".local", "share", "Steam"),
                  os.path.join(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam")]
    return roots


def _libraries(root):
    libs = [root]
    vdf = os.path.join(root, "steamapps", "libraryfolders.vdf")
    try:
        with open(vdf, encoding="utf-8", errors="replace") as f:
            for m in re.finditer(r'"path"\s+"([^"]+)"', f.read()):
                libs.append(os.path.normpath(m.group(1).replace("\\\\", "\\")))
        log.info("paths", f"read Steam library list {vdf}")
    except OSError:
        pass
    return libs


def candidate_games(env=None):
    """Every place a Starfield game folder could be, in search order, without repeats."""
    env = os.environ if env is None else env
    out, seen = [], set()
    places = [os.path.join(lib, "steamapps", "common", "Starfield")
              for root in _steam_roots(env) for lib in _libraries(root)]
    if sys.platform == "win32":
        places += [f"{d}:\\XboxGames\\Starfield\\Content" for d in string.ascii_uppercase]
    for p in places:
        key = os.path.normcase(os.path.normpath(p))
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def find_game(given=None, env=None):
    """(game folder, how it was found) or (None, list of places searched)."""
    if given:
        return (given, "given with --game") if os.path.isdir(given) else (None, [given])
    tried = []
    for p in candidate_games(env):
        tried.append(p)
        if os.path.isfile(os.path.join(p, "Starfield.exe")):
            log.info("paths", f"game folder found: {p}")
            return p, "found automatically"
    return None, tried


def is_game_pass(game):
    """Game Pass installs carry an appxmanifest.xml. (The folder name alone says nothing: a Steam library can sit
    inside a folder called XboxGames.)"""
    return os.path.isfile(os.path.join(game, "appxmanifest.xml"))


def data_folder(game):
    return os.path.join(game, "Data")


def sfse_plugins_folder(game):
    return os.path.join(game, "Data", "SFSE", "Plugins")


# ---- the Creations catalog (creations command) ----------------------------------------------------------------
STARFIELD_APP_ID = "1716740"


def candidate_catalogs(env=None):
    """Where the game keeps ContentCatalog.txt, in search order. The game names it with the same folder as
    Plugins.txt: %LOCALAPPDATA%\\Starfield for Steam and Game Pass alike; under Proton, inside each Steam
    library's compatdata prefix."""
    env = os.environ if env is None else env
    if sys.platform == "win32":
        local = env.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return [os.path.join(local, "Starfield", "ContentCatalog.txt")]
    out, seen = [], set()
    for root in _steam_roots(env):
        for lib in _libraries(root):
            p = os.path.join(lib, "steamapps", "compatdata", STARFIELD_APP_ID, "pfx", "drive_c", "users",
                             "steamuser", "AppData", "Local", "Starfield", "ContentCatalog.txt")
            key = os.path.normpath(p)
            if key not in seen:
                seen.add(key)
                out.append(p)
    return out


def default_saved_catalog(env=None):
    """Where creations keeps its saved copy: %LOCALAPPDATA%\\sf-patch-day on Windows, $XDG_STATE_HOME/sf-patch-day
    (default ~/.local/state) elsewhere."""
    env = os.environ if env is None else env
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    else:
        base = env.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "sf-patch-day", "ContentCatalog-saved.txt")
