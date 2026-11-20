# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""Finds and loads sf-pex-tools (https://github.com/taosecurity/sf-pex-tools), which drift uses to read the
functions in an add-on's compiled scripts. It's optional: without it, record and stage checks still run.

Search order: --pex-tools <folder>, the SF_PEX_TOOLS environment variable, then a folder named sf-pex-tools next
to sf-patch-day's own folder.
"""
import importlib.util
import os

from . import PEX_TOOLS_URL, log

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NEEDED = (0, 1, 0)


class PexTools:
    def __init__(self, folder, ba2, pex):
        self.folder, self.ba2, self.pex = folder, ba2, pex


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def candidates(given=None, env=None):
    env = os.environ if env is None else env
    out = []
    if given:
        out.append(given)
    if env.get("SF_PEX_TOOLS"):
        out.append(env["SF_PEX_TOOLS"])
    out.append(os.path.join(os.path.dirname(HERE), "sf-pex-tools"))
    return out


def find(given=None, env=None):
    """(PexTools or None, message). A folder given with --pex-tools that doesn't hold the tools is an error
    message; the automatic places are only tried."""
    for i, folder in enumerate(candidates(given, env)):
        ba2_path, pex_path = os.path.join(folder, "ba2_extract.py"), os.path.join(folder, "pex_compare.py")
        if not (os.path.isfile(ba2_path) and os.path.isfile(pex_path)):
            log.info("pex-tools", f"not in {folder}")
            if given and i == 0:
                return None, (f"--pex-tools {folder}: ba2_extract.py and pex_compare.py aren't there. Fix: give "
                              f"the folder you unzipped sf-pex-tools into ({PEX_TOOLS_URL}).")
            continue
        try:
            ba2 = _load("sf_pex_tools_ba2_extract", ba2_path)
            pex = _load("sf_pex_tools_pex_compare", pex_path)
        except Exception as e:  # a damaged or foreign file: say so, don't crash
            return None, f"{folder}: sf-pex-tools couldn't be loaded ({type(e).__name__}: {e})"
        ver = tuple(int(x) for x in getattr(ba2, "VERSION", "0.0.0").split(".")[:3] if x.isdigit())
        if ver < NEEDED:
            return None, f"{folder}: sf-pex-tools {getattr(ba2, 'VERSION', '?')} is too old; 0.1.0 or newer is needed"
        log.info("pex-tools", f"using sf-pex-tools {ba2.VERSION} from {folder}")
        return PexTools(folder, ba2, pex), f"sf-pex-tools {ba2.VERSION} ({folder})"
    return None, f"sf-pex-tools not found (install 0.1.0 from {PEX_TOOLS_URL} and give --pex-tools <folder>)"
