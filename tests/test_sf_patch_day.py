# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""sf-patch-day tests. Run: python -I tests/test_sf_patch_day.py

Every DLL and plugin here is made up by tests/makers.py. The function checks use sf-pex-tools' own made-up test
archive; they need sf-pex-tools (SF_PEX_TOOLS, or a sf-pex-tools folder next to this repo) and skip without it.
"""
import argparse
import contextlib
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import makers as mk  # noqa: E402
from sf_patch_day import cli, creations, dlls, drift, framework, log, paths, pe, pextools, scripts  # noqa: E402
try:
    from sf_patch_day import risk  # noqa: E402  (0.5.0)
except ImportError:  # lets the 0.4.0 code run these tests and show them failing
    risk = None
try:
    from sf_patch_day import hints  # noqa: E402  (0.5.0 step 3)
except ImportError:  # lets the step 2 code run these tests and show them failing
    hints = None
from sf_patch_day.plugin import Plugin  # noqa: E402

V244, V300 = mk.game_version(1, 16, 244), mk.game_version(1, 16, 300)


def run(*argv):
    """(exit code, stdout text) of the command line, run in this process."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue()


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class Temp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sf-patch-day-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


# ---- the PE reader --------------------------------------------------------------------------------------------
class TestPE(unittest.TestCase):
    def test_block_round_trip(self):
        data = mk.sfse_plugin(name="Alpha", author="Someone", plugin_version=0x15070000, address=4, structure=8,
                              compatible=[V244], sfse_required=mk.game_version(0, 2, 21))
        b = pe.sfse_block(data)
        self.assertEqual((b["name"], b["author"], b["address"], b["structure"]), ("Alpha", "Someone", 4, 8))
        self.assertEqual(b["compatible"], [V244])
        self.assertEqual(pe.version_text(b["sfse_required"]), "0.2.21")
        self.assertEqual(pe.plugin_version_text(b["plugin_version"]), "21.7.0")
        self.assertEqual(pe.plugin_version_text(2), "2")

    def test_no_export_and_junk(self):
        self.assertIsNone(pe.sfse_block(mk.pe_file()))
        self.assertIsNone(pe.sfse_block(mk.pe_file(b"SomethingElse", b"x" * 16)))
        with self.assertRaises(pe.PEError):
            pe.sfse_block(b"not a program at all" * 10)
        with self.assertRaises(pe.PEError):
            pe.sfse_block(mk.sfse_plugin()[:0x500])  # cut short

    def test_many_sections_refused(self):
        # Round 3, C1: the export readers walk every section for each name, so a file with 65,535 sections stalled
        # them for minutes. They refuse it, as imports() does, and fast.
        import time
        many = bytearray(mk.sfse_plugin(name="Alpha")) + bytes(40 * 65535)
        struct.pack_into("<H", many, 0x46, 65535)
        t = time.time()
        with self.assertRaises(pe.PEError) as cm:
            pe.sfse_block(bytes(many), "Big.dll")
        self.assertIn("65535 sections, more than the 96", str(cm.exception))
        self.assertEqual(pe.PE(bytes(many)).imports()[0], [])
        with self.assertRaises(pe.PEError):
            pe.PE(bytes(many)).export_names()
        self.assertEqual(framework.exports(bytes(many), "Big.dll"), [])
        self.assertLess(time.time() - t, 5)
        # exactly the limit still reads
        ok = bytearray(mk.sfse_plugin(name="Alpha")) + bytes(40 * pe.MAX_SECTIONS)
        struct.pack_into("<H", ok, 0x46, pe.MAX_SECTIONS)
        self.assertEqual(pe.sfse_block(bytes(ok))["name"], "Alpha")
        struct.pack_into("<H", ok, 0x46, pe.MAX_SECTIONS + 1)
        with self.assertRaises(pe.PEError):
            pe.sfse_block(bytes(ok))

    def test_file_version(self):
        self.assertEqual(pe.PE(mk.pe_file(file_version=(1, 16, 300, 0))).file_version(), (1, 16, 300, 0))
        self.assertIsNone(pe.PE(mk.pe_file()).file_version())

    def test_address_library_hint(self):
        self.assertTrue(pe.mentions_address_library(b"..versionlib-{}.bin.."))
        self.assertTrue(pe.mentions_address_library("Data\\SFSE\\Plugins\\versionlib".encode("utf-16-le")))
        self.assertFalse(pe.mentions_address_library(b"nothing here"))


# ---- the verdict rule -------------------------------------------------------------------------------------------
class TestVerdict(unittest.TestCase):
    T = (1, 16, 300)

    def v(self, al=True, sfse=None, **kw):
        return dlls.verdict(pe.sfse_block(mk.sfse_plugin(**kw)), self.T, al, sfse)[0]

    def test_rules(self):
        self.assertEqual(self.v(compatible=[V244]), dlls.LOCKED)
        self.assertEqual(self.v(compatible=[V300]), dlls.WORKS)
        self.assertEqual(self.v(address=4, structure=8), dlls.WORKS)
        self.assertEqual(self.v(al=False, address=4, structure=8), dlls.NEEDS_AL)
        self.assertEqual(self.v(al=False, address=4, structure=8, compatible=[V300]), dlls.NEEDS_AL)
        self.assertEqual(self.v(address=1, structure=1), dlls.MAY_FAIL)
        self.assertEqual(self.v(address=4, structure=0, compatible=[V244]), dlls.LOCKED)  # no structure promise
        self.assertEqual(self.v(address=2, structure=8, compatible=[V244]), dlls.LOCKED)  # old Address Library only
        self.assertEqual(self.v(address=4, structure=8, reserved_breaking=1), dlls.LOCKED)
        self.assertEqual(self.v(data_version=2, address=4, structure=8), dlls.LOCKED)
        self.assertEqual(self.v(sfse=mk.game_version(0, 2, 21), sfse_required=mk.game_version(0, 2, 30),
                                compatible=[V300]), dlls.NEEDS_SFSE)
        self.assertEqual(dlls.verdict(None, self.T, True)[0], dlls.NOT_SFSE)

    def test_parse_game_version(self):
        self.assertEqual(dlls.parse_game_version("1.16.244"), (1, 16, 244))
        self.assertEqual(dlls.parse_game_version("1.16.244.0"), (1, 16, 244))
        self.assertIsNone(dlls.parse_game_version("latest"))


# ---- dlls on a made-up game folder ------------------------------------------------------------------------------
class TestDllsCommand(Temp):
    def make_game(self, with_sfse=True, with_al=False):
        game = self.p("Starfield")
        write(os.path.join(game, "Starfield.exe"), mk.pe_file(file_version=(1, 16, 300, 0)))
        if with_sfse:
            write(os.path.join(game, "sfse_1_16_300.dll"), mk.pe_file(file_version=(0, 0, 2, 30)))
        plugins = os.path.join(game, "Data", "SFSE", "Plugins")
        write(os.path.join(plugins, "Locked.dll"), mk.sfse_plugin(name="Locked", compatible=[V244]))
        write(os.path.join(plugins, "Listed.dll"), mk.sfse_plugin(name="Listed", compatible=[V244, V300]))
        write(os.path.join(plugins, "UsesAL.dll"), mk.sfse_plugin(name="UsesAL", address=4, structure=8,
                                                                   extra=b"versionlib-{}.bin"))
        write(os.path.join(plugins, "Scans.dll"), mk.sfse_plugin(name="Scans", address=1, structure=1))
        write(os.path.join(plugins, "Helper.dll"), mk.pe_file())
        write(os.path.join(plugins, "Broken.dll"), b"MZ" + b"\xff" * 100)
        if with_al:
            write(os.path.join(plugins, "versionlib-1-16-300-0.bin"), b"made-up")
        return game

    def report(self, *argv):
        code, out = run("dlls", "--json", *argv)
        return code, json.loads(out)

    def verdicts(self, rep):
        return {r["file"]: r["verdict"] for r in rep["plugins"]}

    def test_patch_day(self):
        game = self.make_game()
        code, rep = self.report("--game", game)
        self.assertEqual(rep["game_version"], "1.16.300")
        self.assertEqual(pe.version_text(rep["sfse"]["sfse_version"]), "0.2.30")
        self.assertEqual(self.verdicts(rep), {"Locked.dll": dlls.LOCKED, "Listed.dll": dlls.WORKS,
                                              "UsesAL.dll": dlls.NEEDS_AL, "Scans.dll": dlls.MAY_FAIL,
                                              "Helper.dll": dlls.NOT_SFSE, "Broken.dll": dlls.UNREADABLE})
        self.assertEqual(code, 3)  # Broken.dll is unreadable
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Broken.dll"))
        self.assertEqual(self.report("--game", game)[0], 2)  # Locked.dll

    def test_address_library_arrives(self):
        game = self.make_game(with_al=True)
        for f in ("Broken.dll", "Locked.dll"):
            os.remove(os.path.join(game, "Data", "SFSE", "Plugins", f))
        code, rep = self.report("--game", game)
        self.assertEqual(self.verdicts(rep)["UsesAL.dll"], dlls.WORKS)
        self.assertEqual(code, 1)  # Scans.dll may fail
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Scans.dll"))
        self.assertEqual(self.report("--game", game)[0], 0)

    def test_no_sfse_for_version(self):
        game = self.make_game(with_sfse=False, with_al=True)
        for f in ("Broken.dll", "Locked.dll", "Scans.dll"):
            os.remove(os.path.join(game, "Data", "SFSE", "Plugins", f))
        code, rep = self.report("--game", game)
        self.assertFalse(rep["sfse"]["sfse_found"])
        self.assertEqual(code, 1)
        code, out = run("dlls", "--game", game)
        self.assertIn("SFSE: NOT FOUND", out)

    def test_zip_and_version_override(self):
        game = self.make_game(with_al=True)
        z = self.p("download.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SFSE/Plugins/NewMod.dll", mk.sfse_plugin(name="NewMod", address=4, structure=8))
            zf.writestr("readme.txt", "made up")
        code, rep = self.report(z, "--game", game)
        self.assertEqual(self.verdicts(rep), {"download.zip :: SFSE/Plugins/NewMod.dll": dlls.WORKS})
        self.assertEqual(code, 0)  # the game's Address Library file counts; its DLLs aren't judged
        code, rep = self.report(z, "--game-version", "1.16.400")
        self.assertEqual(self.verdicts(rep), {"download.zip :: SFSE/Plugins/NewMod.dll": dlls.NEEDS_AL})

    def test_text_report_and_log(self):
        game = self.make_game()
        logf = self.p("run.log")
        code, out = run("dlls", "--game", game, "--log", logf)
        self.assertIn("Game version: 1.16.300", out)
        self.assertIn("LOCKED", out)
        self.assertIn("what to do:", out)
        with open(logf, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("[dlls]", text)
        self.assertIn("Locked.dll", text)

    def test_one_bad_zip_member_is_only_that_file(self):
        game = self.make_game(with_al=True)
        z = self.p("mixed.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("Locked/Secret.dll", mk.sfse_plugin(name="Secret"))
            zf.writestr("Good.dll", mk.sfse_plugin(name="Good", address=4, structure=8))
        # Mark the first member "encrypted" (bit 0 of its flags, in the local and central headers): reading it then
        # raises RuntimeError, as a password-protected download does.
        with open(z, "rb") as f:
            data = bytearray(f.read())
        data[6] |= 1
        central = data.index(b"PK\x01\x02")
        data[central + 8] |= 1
        with open(z, "wb") as f:
            f.write(data)
        code, rep = self.report(z, "--game", game)
        self.assertEqual(self.verdicts(rep), {"mixed.zip :: Locked/Secret.dll": dlls.UNREADABLE,
                                              "mixed.zip :: Good.dll": dlls.WORKS})
        self.assertEqual(code, 3)

    def test_unreadable_folder_is_reported(self):
        folder = self.p("Plugins")
        os.makedirs(folder)
        real_walk = dlls.os.walk

        def walk(path, onerror=None):
            onerror(PermissionError(13, "Access is denied", path))
            return iter(())
        dlls.os.walk = walk
        try:
            items, _al, problems = dlls.collect([folder])
        finally:
            dlls.os.walk = real_walk
        self.assertEqual(items, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("Access is denied", problems[0][1])

    def test_hint(self):
        path = self.p("Quiet.dll")
        write(path, mk.sfse_plugin(name="Quiet", address=1, structure=1, extra="versionlib".encode("utf-16-le")))
        r = dlls.judge(dlls.Item("Quiet.dll", path), (1, 16, 300), False, None)
        self.assertEqual(r["verdict"], dlls.MAY_FAIL)
        self.assertIn("names an Address Library file", r["hint"])

    def test_round3_xboxgames_folder_name_alone_is_not_game_pass(self):
        """(0.5.3, Round 3 C6) A Steam library inside a folder named XboxGames is still Steam: Game Pass installs
        are told apart by their appxmanifest.xml."""
        game = self.make_game()
        inside = os.path.join(self.p("XboxGames", "SteamLibrary"), "Starfield")
        shutil.copytree(game, inside)
        self.assertFalse(paths.is_game_pass(inside))
        code, out = run("dlls", "--game", inside)
        self.assertNotIn("Game Pass install", out)
        write(os.path.join(inside, "appxmanifest.xml"), b"<made-up/>")
        self.assertTrue(paths.is_game_pass(inside))

    def test_game_pass_and_errors(self):
        game = self.make_game(with_sfse=False)
        write(os.path.join(game, "appxmanifest.xml"), b"<made-up/>")
        code, out = run("dlls", "--game", game)
        self.assertIn("SFSE: this is a Game Pass install, and SFSE doesn't support Game Pass", out)
        self.assertEqual(code, 3)  # Broken.dll; without it, Game Pass alone gives 2
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Broken.dll"))
        code, out = run("dlls", "--game", game)
        self.assertEqual(code, 2)
        self.assertIn("don't load on the Game Pass version, and some are locked", out)
        only_helpers = self.p("helpers")
        write(os.path.join(only_helpers, "Helper.dll"), mk.pe_file())
        # No SFSE plugin checked: nothing waits for an update, and on Game Pass the missing SFSE isn't news.
        code, out = run("dlls", only_helpers, "--game", game)
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("Game Pass install"), 1, out)  # said once
        self.assertNotIn("waits for an SFSE update", out)
        # Round 3, C2: no Data\SFSE\Plugins folder means no SFSE plugins installed, not a read failure.
        shutil.rmtree(os.path.join(game, "Data", "SFSE"))
        code, out = run("dlls", "--game", game)
        self.assertEqual(code, 0, out)
        self.assertIn("no SFSE plugins are installed", out)
        self.assertNotIn("CANNOT READ", out)
        self.assertIn("Game Pass install", out)
        os.remove(os.path.join(game, "appxmanifest.xml"))
        steam = self.make_game()
        shutil.rmtree(os.path.join(steam, "Data", "SFSE"))
        code, out = run("dlls", "--game", steam)
        self.assertEqual(code, 0, out)
        self.assertNotIn("CANNOT READ", out)
        self.assertEqual(run("dlls", "--game", self.p("nowhere"))[0], 3)
        self.assertEqual(run("dlls", self.p("x.zip"), "--game-version", "soon")[0], 3)
        self.assertEqual(run("dlls", self.p("missing.dll"), "--game-version", "1.16.300")[0], 3)
        self.assertEqual(run("dlls", "--no-such-option")[0], 3)

    def test_plugins_folder_spelled_in_other_case(self):
        """On a case-sensitive system (Linux, Proton) a Data/sfse/plugins folder is still the plugins folder: its
        DLLs are checked, not reported as "no SFSE plugins are installed". Runs as on Linux on any system: a folder
        exists only under the exact spelling stored on disk."""
        from unittest import mock
        game = self.make_game()
        data = os.path.join(game, "Data")
        os.rename(os.path.join(data, "SFSE"), os.path.join(data, "sfse_tmp"))  # two steps: Windows ignores case
        os.rename(os.path.join(data, "sfse_tmp"), os.path.join(data, "sfse"))
        os.rename(os.path.join(data, "sfse", "Plugins"), os.path.join(data, "sfse", "plugins_tmp"))
        os.rename(os.path.join(data, "sfse", "plugins_tmp"), os.path.join(data, "sfse", "plugins"))
        root = os.path.abspath(game)
        real_isdir, real_listdir = os.path.isdir, os.listdir

        def isdir(p):
            p = os.path.abspath(p)
            if not os.path.normcase(p).startswith(os.path.normcase(root)):
                return real_isdir(p)
            cur = root
            for part in os.path.relpath(p, root).split(os.sep):
                if part in ("", "."):
                    continue
                if part not in real_listdir(cur):
                    return False
                cur = os.path.join(cur, part)
            return real_isdir(cur)
        with mock.patch.object(os.path, "isdir", isdir):
            self.assertFalse(os.path.isdir(os.path.join(data, "SFSE", "Plugins")))  # the emulation works
            code, out = run("dlls", "--game", game)
        self.assertNotIn("no SFSE plugins are installed", out)
        self.assertIn("Listed.dll", out)
        self.assertIn("Broken.dll", out)
        self.assertEqual(code, 3, out)  # Broken.dll can't be read, as with the usual spelling

    def test_unreadable_sfse_folder_is_not_called_empty(self):
        """(0.5.3 code-review round 4) A Data\\SFSE folder this account can't read (an update dropped the read
        grant) is a CANNOT READ and exit 3, as in 0.5.2, not "no SFSE plugins are installed" and an all-clear.
        Emulates what Windows does with a deny entry on Data\\SFSE: listing it fails and its Plugins folder
        doesn't seem to be there."""
        from unittest import mock
        game = self.make_game()
        os.remove(os.path.join(game, "Data", "SFSE", "Plugins", "Broken.dll"))  # else exit 3 either way
        self.assertNotEqual(run("dlls", "--game", game)[0], 3)  # readable: nothing fails to read
        sfse = os.path.normcase(os.path.abspath(os.path.join(game, "Data", "SFSE")))
        real_isdir, real_listdir = os.path.isdir, os.listdir

        def isdir(p):
            if os.path.normcase(os.path.abspath(p)).startswith(sfse + os.sep):
                return False
            return real_isdir(p)

        def listdir(p="."):
            if os.path.normcase(os.path.abspath(p)).startswith(sfse):
                raise PermissionError(13, "Access is denied", p)
            return real_listdir(p)
        with mock.patch.object(os.path, "isdir", isdir), mock.patch.object(os, "listdir", listdir):
            code, out = run("dlls", "--game", game)
        self.assertNotIn("no SFSE plugins are installed", out)
        self.assertIn("CANNOT READ", out)
        self.assertEqual(code, 3, out)


# ---- which framework a plugin was built with ----------------------------------------------------------------------
class TestFramework(Temp):
    def judge(self, path):
        return dlls.judge(dlls.collect([path])[0][0], (1, 16, 300), True, None)

    def one(self, name, data, pdb=None):
        folder = self.p("Plugins")
        write(os.path.join(folder, name), data)
        if pdb is not None:
            write(os.path.join(folder, name[:-4] + ".pdb"), pdb)
        return self.judge(os.path.join(folder, name))

    def test_commonlibsf(self):
        r = self.one("Clsf.dll", mk.sfse_plugin(address=4, structure=8, exports=[b"SFSEPlugin_Load"],
                                                extra=mk.COMMONLIBSF_TEXT + b"Address Library\0"))
        self.assertEqual(r["framework"], "CommonLibSF")
        self.assertEqual(r["framework_why"], "2 CommonLibSF source paths, commonlib-shared, 3 RE type names")
        ev = r["framework_evidence"]
        self.assertEqual((ev["commonlibsf_paths"], ev["commonlib_shared"], ev["re_types"], ev["sfse_paths"]),
                         (2, True, 3, 0))
        self.assertEqual(ev["exports"], ["SFSEPlugin_Load", "SFSEPlugin_Version"])
        self.assertIsNone(ev["pdb"])
        self.assertIsNone(ev["pdb_counts"])
        self.assertTrue(r["uses_address_library"])
        self.assertEqual(r["address_library_evidence"], ["version data", "Address Library text"])

    def test_plain_sfse(self):
        r = self.one("Plain.dll", mk.sfse_plugin(address=1, structure=1, extra=mk.PLAIN_SFSE_TEXT))
        self.assertEqual((r["framework"], r["framework_why"]), ("plain SFSE", "1 SFSE source path; no CommonLibSF signs"))
        self.assertFalse(r["uses_address_library"])
        self.assertEqual(r["address_library_evidence"], [])

    def test_cant_tell(self):
        r = self.one("Quiet.dll", mk.sfse_plugin(address=1, structure=1))
        self.assertEqual((r["framework"], r["framework_why"]), ("can't tell", "no CommonLibSF or SFSE source signs"))
        # The bare word is not a sign: another library may name an old CommonLibSF file format.
        r = self.one("Word.dll", mk.sfse_plugin(extra=b"\0CommonLibSF-Offsets-v{}.bin\0versionlib\0"))
        self.assertEqual(r["framework"], "can't tell")
        self.assertEqual(r["address_library_evidence"], ["versionlib file name"])
        # Two RE names are below the threshold; with an SFSE source path the plugin is plain SFSE.
        two = b"\0.?AVAlpha@RE@@\0.?AVBeta@RE@@\0"
        r = self.one("Two.dll", mk.sfse_plugin(extra=two))
        self.assertEqual((r["framework"], r["framework_why"]),
                         ("can't tell", "2 RE type names, fewer than 3; no other CommonLibSF or SFSE source signs"))
        r = self.one("TwoPlain.dll", mk.sfse_plugin(extra=two + mk.PLAIN_SFSE_TEXT))
        self.assertEqual(r["framework"], "plain SFSE")
        # CommonLibSF wins when SFSE source paths are there too.
        r = self.one("Both.dll", mk.sfse_plugin(extra=mk.COMMONLIBSF_TEXT + mk.PLAIN_SFSE_TEXT))
        self.assertEqual(r["framework"], "CommonLibSF")
        self.assertIn("1 SFSE source path", r["framework_why"])

    def test_pdb_beside_the_dll(self):
        r = self.one("Sym.dll", mk.sfse_plugin(), pdb=b"made-up PDB" + mk.CLSF_PDB_TEXT)
        self.assertEqual(r["framework"], "CommonLibSF")
        self.assertEqual(r["framework_why"], "1 CommonLibSF source path in its PDB, 4 RE type names in its PDB")
        self.assertTrue(r["framework_evidence"]["pdb"].endswith("Sym.pdb"))
        self.assertEqual(r["framework_evidence"]["pdb_counts"]["re_types"], 4)
        r = self.one("Mixed.dll", mk.sfse_plugin(extra=mk.COMMONLIBSF_TEXT), pdb=mk.CLSF_PDB_TEXT)
        self.assertIn("2 CommonLibSF source paths in the DLL, 1 in its PDB", r["framework_why"])
        # The same class named in the DLL and its PDB is not counted twice: 2 and 1 stay below the threshold of 3.
        r = self.one("Twice.dll", mk.sfse_plugin(extra=b"\0.?AVAlpha@RE@@\0.?AVBeta@RE@@\0"), pdb=b"\0RE::Alpha\0")
        self.assertEqual((r["framework"], r["framework_why"]), ("can't tell", "2 RE type names in the DLL, 1 in its "
                         "PDB, fewer than 3; no other CommonLibSF or SFSE source signs"))
        r = self.one("Empty.dll", mk.sfse_plugin(), pdb=b"")
        self.assertEqual(r["framework"], "can't tell")  # an empty PDB is skipped
        self.assertIsNone(r["framework_evidence"]["pdb"])

    def test_pdb_in_a_zip(self):
        z = self.p("download.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SFSE/Plugins/Sym.dll", mk.sfse_plugin())
            zf.writestr("SFSE/Plugins/Sym.pdb", mk.CLSF_PDB_TEXT)
            zf.writestr("SFSE/Plugins/Alone.dll", mk.sfse_plugin())
            zf.writestr("Other/Alone.pdb", mk.CLSF_PDB_TEXT)  # another folder: not beside it
        rs = {r["file"]: r for r in (dlls.judge(i, (1, 16, 300), True, None) for i in dlls.collect([z])[0])}
        self.assertEqual(rs["download.zip :: SFSE/Plugins/Sym.dll"]["framework"], "CommonLibSF")
        self.assertTrue(rs["download.zip :: SFSE/Plugins/Sym.dll"]["framework_evidence"]["pdb"].endswith(
            ":: SFSE/Plugins/Sym.pdb"))
        self.assertEqual(rs["download.zip :: SFSE/Plugins/Alone.dll"]["framework"], "can't tell")

    def test_empty_pdb_in_a_zip_is_logged_as_empty(self):
        from unittest import mock
        z = self.p("empty-pdb.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("SFSE/Plugins/E.dll", mk.sfse_plugin())
            zf.writestr("SFSE/Plugins/E.pdb", b"")
        with mock.patch.object(dlls.log, "info") as info:
            r = dlls.judge(dlls.collect([z])[0][0], (1, 16, 300), True, None)
        self.assertIsNone(r["framework_evidence"]["pdb"])
        said = [c.args[1] for c in info.call_args_list if c.args[0] == "framework"]
        self.assertTrue(any(s.endswith("E.pdb: skipped (empty)") for s in said), said)

    def test_report_json_text_and_exit(self):
        folder = self.p("Plugins")
        write(os.path.join(folder, "Clsf.dll"), mk.sfse_plugin(compatible=[V300], extra=mk.COMMONLIBSF_TEXT))
        write(os.path.join(folder, "Plain.dll"), mk.sfse_plugin(compatible=[V300], extra=mk.PLAIN_SFSE_TEXT))
        write(os.path.join(folder, "Quiet.dll"), mk.sfse_plugin(compatible=[V300]))
        write(os.path.join(folder, "Helper.dll"), mk.pe_file(extra=mk.COMMONLIBSF_TEXT))
        code, out = run("dlls", "--json", "--game-version", "1.16.300", folder)
        rep = json.loads(out)
        self.assertEqual(code, 0)  # the framework is information, not a verdict
        self.assertEqual(rep["frameworks"], {"CommonLibSF": 1, "plain SFSE": 1, "can't tell": 1})
        helper = next(r for r in rep["plugins"] if r["file"] == "Helper.dll")
        self.assertNotIn("framework", helper)  # not an SFSE plugin: no framework fields
        for r in rep["plugins"]:
            if r["file"] != "Helper.dll":
                self.assertTrue({"framework", "framework_why", "framework_evidence", "uses_address_library",
                                 "address_library_evidence"} <= set(r))
        code, out = run("dlls", "--game-version", "1.16.300", folder)
        self.assertEqual(code, 0)
        self.assertIn("    framework: CommonLibSF (2 CommonLibSF source paths, commonlib-shared, 3 RE type names); "
                      "Address Library: no signs", out)
        self.assertIn("    framework: plain SFSE (1 SFSE source path; no CommonLibSF signs)", out)
        self.assertIn("Frameworks: CommonLibSF 1, plain SFSE 1, can't tell 1\nRisk evidence: ", out)

    def test_export_names(self):
        self.assertEqual(pe.PE(mk.pe_file([b"A", b"B"], b"x" * 8)).export_names(), {b"A", b"B"})
        self.assertEqual(pe.PE(mk.pe_file()).export_names(), set())


# ---- the import and risk summary (every DLL and import list here is made up) ------------------------------------
K32 = "KERNEL32.dll"


class TestRisk(Temp):
    def judge(self, name, data):
        path = self.p("Plugins", name)
        write(path, data)
        return dlls.judge(dlls.Item(name, path), (1, 16, 300), True, None)

    def line(self, data, name="Made.dll"):
        return risk.text_line(self.judge(name, data)["risk"], None)

    def test_pe_imports(self):
        imports = [(K32, ["VirtualProtect", "GetProcAddress"], False), ("WS2_32.dll", [115, 116, 9999], False),
                   ("winhttp.dll", ["WinHttpOpen"], True)]
        want = ([("kernel32.dll", ["VirtualProtect", "GetProcAddress"], False),
                 ("ws2_32.dll", ["#115", "#116", "#9999"], False), ("winhttp.dll", ["WinHttpOpen"], True)], 0, None)
        self.assertEqual(pe.PE(mk.pe_file(imports=imports)).imports(), want)
        self.assertEqual(pe.PE(mk.pe_file(imports=imports, bits=32)).imports(), want)  # PE32 too
        self.assertEqual(pe.PE(mk.pe_file()).imports(), ([], 0, None))

    def test_pe_imports_limits(self):
        # Bug hunt 0.5.0: the function-entry limit is for the whole file, so many imported DLLs (or descriptors
        # sharing one long table) can't make a small hostile file read millions of names.
        from unittest import mock
        data = mk.pe_file(imports=[(f"x{i}.dll", [f"F{j}" for j in range(40)], False) for i in range(10)])
        with mock.patch.object(pe, "MAX_THUNKS", 50):
            entries, skipped, stopped = pe.PE(data).imports()
        self.assertLessEqual(sum(len(f) for _d, f, _x in entries), 50)
        self.assertEqual(skipped, 0)
        self.assertEqual(stopped, "reading stopped at the limit of 50 function entries; the rest isn't read")
        self.assertEqual(len(entries), 2)  # reading stops once the limit is used up
        # More sections than this tool reads: the imports aren't read (each lookup walks every section), and the
        # line says so instead of "none of the four kinds in its imports" (code-review round 1, 0.5.0).
        many = bytearray(mk.pe_file(imports=[(K32, ["CreateProcessW"], False)], extra=bytes(8192)))
        struct.pack_into("<H", many, 0x46, pe.MAX_SECTIONS + 1)
        self.assertEqual(pe.PE(bytes(many)).imports(),
                         ([], 0, "the file has 97 sections, more than the 96 this tool reads, so no imports were read"))
        # Round 3, C1: judge() refuses the file too (the export readers walk every section), and names the limit.
        r = self.judge("Many.dll", bytes(many))
        self.assertEqual(r["verdict"], dlls.UNREADABLE)
        self.assertIn("97 sections, more than the 96", r["reason"])
        many[0x46:0x48] = struct.pack("<H", pe.MAX_SECTIONS)
        self.assertEqual(pe.PE(bytes(many)).imports()[0], [("kernel32.dll", ["CreateProcessW"], False)])

    def test_imported_dll_limit_said(self):
        # Code-review round 2, 0.5.0: a DLL past the imported-DLL limit is a limit, not "1 entry skipped", and
        # exactly the limit followed by the end mark is a whole table.
        from unittest import mock
        data = mk.pe_file(imports=[(K32, ["F1"], False), ("x.dll", ["F2"], False), ("ws2_32.dll", ["connect"], False)])
        with mock.patch.object(pe, "MAX_IMPORT_DLLS", 2):
            self.assertEqual(pe.PE(data).imports(),
                             ([("kernel32.dll", ["F1"], False), ("x.dll", ["F2"], False)], 0,
                              "reading stopped at the limit of 2 imported DLLs in one table; the rest isn't read"))
        with mock.patch.object(pe, "MAX_IMPORT_DLLS", 3):
            self.assertEqual(pe.PE(data).imports()[1:], (0, None))

    def test_limit_used_up_before_delay_table(self):
        # Code-review round 1, 0.5.0: regular imports that use up the entry limit exactly can't hide the
        # delay-loaded ones without a note.
        from unittest import mock
        data = mk.pe_file(imports=[(K32, ["F1", "F2", "F3"], False), ("ws2_32.dll", ["connect"], True)])
        with mock.patch.object(pe, "MAX_THUNKS", 4):  # three names and the end mark
            entries, skipped, stopped = pe.PE(data).imports()
            r = self.judge("Hide.dll", data)
        self.assertEqual(entries, [("kernel32.dll", ["F1", "F2", "F3"], False)])
        self.assertEqual(stopped, "reading stopped at the limit of 4 function entries; the rest isn't read")
        self.assertIn("(import table not fully read: reading stopped at the limit of 4 function entries",
                      risk.text_line(r["risk"], r["imports"]["problem"]))
        self.assertEqual(risk.summary_line({k: 0 for k in risk.KINDS}, 2, 1),
                         "Risk evidence: network 0, process launch 0, runtime DLL loading 0, code patching 0 "
                         "(of 2 DLLs read; 1 with the import table not fully read)")

    def test_delay_descriptor_without_name_table(self):
        # Code-review round 1, 0.5.0: a delay-load descriptor with no name table is skipped; its IAT holds stub
        # code addresses, not names.
        data = bytearray(mk.pe_file(imports=[("ws2_32.dll", ["connect"], True)]))
        p = pe.PE(bytes(data))
        struct.pack_into("<I", data, p.off(p.dirs[13][0]) + 16, 0)  # the name table's RVA
        self.assertEqual(pe.PE(bytes(data)).imports(), ([], 1, None))

    def test_each_kind_text_and_json(self):
        r = self.judge("All.dll", mk.sfse_plugin(compatible=[V300], imports=[
            (K32, ["CreateProcessW", "LoadLibraryW", "GetProcAddress", "VirtualProtect", "FlushInstructionCache",
                   "WriteProcessMemory", "GetModuleHandleW"], False),
            ("ws2_32.dll", ["getaddrinfo", "WSAStartup", "connect", "send", "recv", "closesocket"], False)]))
        self.assertEqual(risk.text_line(r["risk"]), (
            "    risk evidence (not a verdict): network (ws2_32.dll: getaddrinfo, WSAStartup, connect, send, +2 more); "
            "process launch (CreateProcessW); runtime DLL loading (LoadLibraryW, GetProcAddress); "
            "code patching (VirtualProtect, FlushInstructionCache; other processes: WriteProcessMemory)"))
        self.assertEqual(r["risk"]["process_launch"], {"imports": ["kernel32.dll!CreateProcessW"], "note": None})
        self.assertEqual(r["risk"]["code_patching"]["other_process"], ["kernel32.dll!WriteProcessMemory"])
        self.assertIsNone(r["risk"]["code_patching"]["note"])  # another process: not the common case
        self.assertEqual(r["imports"], {"dlls": ["kernel32.dll", "ws2_32.dll"], "count": 13, "delayed": [],
                                        "problem": None})

    def test_ordinals_named(self):
        line = self.line(mk.pe_file(imports=[("WS2_32.dll", [115, 116, 23, 9999], False)]))
        self.assertIn("network (ws2_32.dll: WSAStartup, WSACleanup, socket, #9999)", line)
        line = self.line(mk.pe_file(imports=[("WSOCK32.dll", [112], False), ("winhttp.dll", [7], False)]))
        self.assertIn("network (wsock32.dll: WSASetLastError; winhttp.dll: #7)", line)  # winhttp ordinals: numbers

    def test_common_notes(self):
        self.assertEqual(self.line(mk.pe_file(imports=[(K32, ["VirtualProtect", "FlushInstructionCache",
                                                               "LoadLibraryExW", "GetProcAddress"], False)])),
                         "    risk evidence (not a verdict): runtime DLL loading (LoadLibraryExW, GetProcAddress) "
                         "[the C runtime imports these itself]; code patching (VirtualProtect, FlushInstructionCache) "
                         "[most SFSE plugins have this (SFSE's hooks need it)]")
        self.assertEqual(self.line(mk.pe_file(imports=[("SHELL32.dll", ["ShellExecuteW"], False)])),
                         "    risk evidence (not a verdict): process launch (ShellExecuteW) "
                         "[also opens web pages and folders]")
        # LoadLibraryW is not what the C runtime brings: no note.
        self.assertIn("runtime DLL loading (LoadLibraryW, GetProcAddress); ",
                      self.line(mk.pe_file(imports=[(K32, ["LoadLibraryW", "GetProcAddress", "VirtualProtect"],
                                                     False)])))
        # Patching-library text takes the note away too.
        self.assertIn("code patching (VirtualProtect; text: Xbyak, MinHook)",
                      self.line(mk.pe_file(imports=[(K32, ["VirtualProtect"], False)],
                                           extra=b"\0.?AVCodeGenerator@Xbyak@@\0MH_ERROR_NOT_INITIALIZED\0")))

    def test_api_set_dll_and_delay_load(self):
        r = self.judge("Api.dll", mk.pe_file(imports=[
            ("api-ms-win-core-processthreads-l1-1-0.dll", ["CreateProcessW"], False),
            ("WINHTTP.dll", ["WinHttpOpen", "WinHttpSendRequest"], True)]))
        self.assertEqual(r["risk"]["process_launch"]["imports"],
                         ["api-ms-win-core-processthreads-l1-1-0.dll!CreateProcessW"])
        self.assertEqual(r["risk"]["network"]["imports"], ["winhttp.dll!WinHttpOpen", "winhttp.dll!WinHttpSendRequest"])
        self.assertEqual(r["imports"]["delayed"], ["winhttp.dll"])

    def test_nothing_found(self):
        self.assertEqual(self.line(mk.pe_file(imports=[(K32, ["GetModuleHandleW", "CloseHandle"], False)])),
                         "    risk evidence (not a verdict): none of the four kinds in its imports")
        self.assertEqual(self.line(mk.sfse_plugin()), "    risk evidence (not a verdict): none of the four kinds in "
                                                      "its imports")

    def test_damaged_descriptor(self):
        r = self.judge("Bad.dll", mk.sfse_plugin(compatible=[V300], imports=[
            (mk.BAD_IMPORT, [], False), (K32, ["CreateProcessW"], False)]))
        self.assertEqual(r["verdict"], dlls.WORKS)
        self.assertEqual(r["imports"]["problem"], "1 entry skipped")
        self.assertEqual(r["imports"]["dlls"], ["kernel32.dll"])  # the next entry is still read
        self.assertEqual(risk.text_line(r["risk"], r["imports"]["problem"]),
                         "    risk evidence (not a verdict): process launch (CreateProcessW) "
                         "(import table not fully read: 1 entry skipped)")

    def test_only_our_own_strings(self):
        evil = "evil\x1b[2J\nRESULT: fake"
        r = self.judge("Odd.dll", mk.pe_file(imports=[("bad\x01name.dll", [evil, "CreateProcessW"], False),
                                                       ("ws2_32.dll", [evil, "send"], False),
                                                       ("wsock32.dll", [evil], False)]))
        self.assertEqual(r["imports"]["dlls"], ["bad\\x01name.dll", "ws2_32.dll", "wsock32.dll"])
        self.assertEqual(r["risk"]["process_launch"]["imports"], ["bad\\x01name.dll!CreateProcessW"])
        line = risk.text_line(r["risk"])
        self.assertEqual(line, "    risk evidence (not a verdict): network (ws2_32.dll: send, +1 more; "
                               "wsock32.dll: 1 function); process launch (CreateProcessW)")
        self.assertEqual(r["risk"]["network"]["unlisted"], {"ws2_32.dll": 1, "wsock32.dll": 1})

    def test_text_report_escapes_every_dll_string(self):
        # 0.5.1: the author (and every other string a DLL, a zip member name or a file name can hold) never reaches
        # the terminal with a control character in it: no ESC, no C1 control (CSI), no newline that fakes a line.
        folder = self.p("Plugins")
        write(os.path.join(folder, "Evil.dll"), mk.sfse_plugin(
            name="Nm\x1b[31m", author="Au\x1b[2J\nRESULT: fake\x9b", compatible=[V300]))
        with zipfile.ZipFile(os.path.join(folder, "Pack.zip"), "w") as z:
            z.writestr("bad\x1b[2Jname\n.dll", b"MZ" + b"\xff" * 100)
        code, out = run("dlls", "--game-version", "1.16.300", folder)
        for ch in ("\x1b", "\x9b", "\x00"):
            self.assertNotIn(ch, out)
        self.assertIn("by Au\\x1b[2J\\x0aRESULT: fake\\x9b", out)
        self.assertIn("bad\\x1b[2Jname\\x0a.dll", out)
        self.assertEqual(len([ln for ln in out.splitlines() if ln.startswith("RESULT:")]), 1, out)
        self.assertEqual(dlls.show("a\x1b\n\x7f\x85\u2028\u202eb"), "a\\x1b\\x0a\\x7f\\x85\\u2028\\u202eb")
        self.assertEqual(dlls.show("plain text, \xe9 and 'quotes' stay"), "plain text, \xe9 and 'quotes' stay")
        self.assertEqual(dlls.show("a\U000e0001x"), "a\\U000e0001x")
        # the troubleshooting log (--verbose, --log) escapes the same way: a zip member name can't fake a log line
        logf = self.p("run.log")
        run("dlls", "--game-version", "1.16.300", folder, "--log", logf)
        with open(logf, encoding="utf-8") as f:
            logged = f.read()
        self.assertIn("bad\\x1b[2Jname\\x0a.dll", logged)
        self.assertNotIn("\x1b", logged)
        self.assertFalse([ln for ln in logged.splitlines() if not re.match(r"\d\d:\d\d:\d\d \[", ln)], logged)
        # a lone surrogate (an undecodable file name) is escaped, so a strict UTF-8 log write can't fail on it
        self.assertEqual(dlls.show("a\udc9bb"), "a\\udc9bb")
        # an unexpected error: the traceback keeps one log line per frame line, and the exception's own text (which
        # can hold a zip member name) stays on one escaped line, so it can't fake a log line either
        from unittest import mock

        def boom(args):
            raise ValueError("bad\n12:00:00 [end] exit code 0")
        with mock.patch.object(cli, "cmd_dlls", boom):
            code, out = run("dlls", "--game-version", "1.16.300", folder, "--log", logf)
        self.assertEqual(code, cli.CANNOT)
        # on screen too: the RESULT line holds the exception text escaped, so it can't print a line of its own
        self.assertIn("RESULT: CANNOT CHECK: unexpected error (ValueError: bad\\x0a12:00:00 [end] exit code 0)", out)
        self.assertFalse([ln for ln in out.splitlines() if ln.startswith("12:00:00")], out)
        with open(logf, encoding="utf-8") as f:
            got = f.read().splitlines()
        self.assertFalse([ln for ln in got if not re.match(r"\d\d:\d\d:\d\d \[", ln)], got)
        self.assertEqual([ln for ln in got if "[end]" in ln[:20]], [got[-1]], got)
        self.assertIn("[error] Traceback (most recent call last):", got[1])
        self.assertTrue(any(ln[9:].startswith('[error]   File "') for ln in got), got)
        self.assertTrue(any("ValueError: bad\\x0a12:00:00 [end] exit code 0" in ln for ln in got), got)

    def test_report_text_json_summary_and_log(self):
        folder = self.p("Plugins")
        write(os.path.join(folder, "Net.dll"), mk.sfse_plugin(compatible=[V300], imports=[
            ("ws2_32.dll", [115], True), (K32, ["VirtualProtect"], False)]))
        write(os.path.join(folder, "Quiet.dll"), mk.sfse_plugin(compatible=[V300], imports=[
            (K32, ["VirtualProtect"], False)]))
        write(os.path.join(folder, "Helper.dll"), mk.pe_file(imports=[("SHELL32.dll", ["ShellExecuteW"], False)]))
        write(os.path.join(folder, "Broken.dll"), b"MZ" + b"\xff" * 100)
        logf = self.p("run.log")
        code, out = run("dlls", "--game-version", "1.16.300", folder, "--log", logf)
        self.assertEqual(code, 3)  # Broken.dll, as before
        self.assertIn("NOT AN SFSE PLUGIN     Helper.dll\n    risk evidence (not a verdict): process launch "
                      "(ShellExecuteW) [also opens web pages and folders]\n    why:", out)  # a helper DLL gets it too
        self.assertIn("    framework: can't tell (no CommonLibSF or SFSE source signs); Address Library: no signs\n"
                      "    framework hints: none (a stripped or packed DLL leaves none)\n"
                      "    risk evidence (not a verdict): network (ws2_32.dll: WSAStartup); code patching "
                      "(VirtualProtect) [most SFSE plugins have this (SFSE's hooks need it)]\n    why:", out)
        self.assertIn("Frameworks: CommonLibSF 0, plain SFSE 0, can't tell 2\nRisk evidence: network 1, process launch "
                      "1, runtime DLL loading 0, code patching 2 (of 3 DLLs read)\nRESULT:", out)
        broken = out[out.index("Broken.dll"):].split("\n")[1]
        self.assertTrue(broken.startswith("    why:"), broken)  # unreadable: no risk line
        with open(logf, encoding="utf-8") as f:
            self.assertIn("[risk] Net.dll: 2 import DLL entries, 2 functions, 0 skipped; kinds: network, "
                          "code_patching", f.read())
        code, out = run("dlls", "--json", "--game-version", "1.16.300", folder)
        rep = json.loads(out)
        self.assertEqual(rep["risk_counts"], {"network": 1, "process_launch": 1, "dll_loading": 0,
                                              "code_patching": 2})
        self.assertEqual(rep["risk_dlls_read"], 3)
        broken = next(r for r in rep["plugins"] if r["file"] == "Broken.dll")
        self.assertNotIn("risk", broken)

    def test_verdict_and_exit_unchanged(self):
        loud = [(K32, ["CreateProcessW", "WriteProcessMemory", "LoadLibraryW"], False), ("ws2_32.dll", [23], True)]
        for n, kw in enumerate(({"compatible": [V244]}, {"address": 1, "structure": 1}, {"compatible": [V300]})):
            outs = []
            for imports in ((), loud):
                folder = self.p(f"V{n}-{len(outs)}")
                write(os.path.join(folder, "X.dll"), mk.sfse_plugin(imports=imports, **kw))
                code, out = run("dlls", "--json", "--game-version", "1.16.300", folder)
                r = json.loads(out)["plugins"][0]
                outs.append((code, r["verdict"], r["reason"]))
            self.assertEqual(outs[0], outs[1], kw)


# ---- signature-scan evidence (every pattern, word and type name here is made up) ----------------------------------
NO_SIGNS_HOW = "says signature scans, but no pattern-scan signs found"
NO_SIGNS_WHY = ("version independent by its version data's signature-scan claim, but no pattern-scan signs were "
                "found (not proof: a scanner can keep its patterns as byte arrays), so it may use fixed addresses "
                "and refuse to load or crash on this version")
NO_SIGNS_TODO = ("SFSE loads it, but it may use fixed addresses that changed on this version. Test it, or check its "
                 "page")


class TestScanEvidence(Temp):
    def judge(self, name, **kw):
        path = self.p("Plugins", name)
        write(path, mk.sfse_plugin(**kw))
        return dlls.judge(dlls.Item(name, path), (1, 16, 300), True, None)

    def test_evidence_found(self):
        r = self.judge("Wild.dll", address=1, structure=1, extra=b"\x0048 8B 05 ?? ?? ?? ?? E8\0")
        self.assertEqual(r["signature_scan_evidence"], ["1 pattern string"])
        self.assertEqual(r["how"], "signature scans; no game structures")
        self.assertEqual((r["verdict"], r["reason"]), (dlls.MAY_FAIL, "version independent by signature scans"))
        self.assertEqual(r["what_to_do"], dlls.WHAT_TO_DO[dlls.MAY_FAIL])
        # Two tokens with a letter A-F are enough without a wildcard; scanner words and type names count too.
        r = self.judge("Hex.dll", address=1, structure=1, extra=b"\x0040 53 48 83 EC 20 8B D9\0Made FindPattern\0"
                       b".?AVMemoryScanner@made@@\0.?AVPatternHit@made@@\0")
        self.assertEqual(r["signature_scan_evidence"], ["1 pattern string", "scanner text: findpattern",
                                                        "2 Pattern/Scanner type names"])
        self.assertEqual(r["how"], "signature scans; no game structures")
        r = self.judge("Words.dll", address=1, structure=1, extra=b"\0made SIGNATURE NOT FOUND, aob scan\0")
        self.assertEqual(r["signature_scan_evidence"], ["scanner text: aob scan, signature not found"])
        r = self.judge("Said.dll", address=1, structure=1, extra=b"\0Made sig not found\0Failed to resolve signature "
                                                                  b"at {}\0")
        self.assertEqual(r["signature_scan_evidence"], ["scanner text: sig not found, resolve signature"])

    def test_one_letter_pattern_and_find_pattern(self):
        # (0.5.2) A wildcard-free pattern with one A-F byte (push rbx; sub rsp, 20h) counts, and so does the
        # scanner text "find pattern" (as in a "Failed to find pattern" message).
        r = self.judge("One.dll", address=1, structure=1, extra=b"\x0040 53 48 83 EC 20\0")
        self.assertEqual(r["signature_scan_evidence"], ["1 pattern string"])
        self.assertEqual(r["how"], "signature scans; no game structures")
        r = self.judge("Find.dll", address=1, structure=1, extra=b"\0Made: failed to Find Pattern for {}\0")
        self.assertEqual(r["signature_scan_evidence"], ["scanner text: find pattern"])

    def test_no_evidence(self):
        # Digit-only number tables, five tokens, bare AOB/AoB, an unbounded pattern, other kinds of signature (a
        # web header, a shader's root signature), the game's hand scanner and spdlog's pattern_formatter are not
        # signs of a pattern scanner.
        extra = (b"\x0010 20 30 40 50 60 70\0" b"11 22 33 44 55 66\0" b"?? ?? ?? ?? ??\0AOB\0AoB\0"
                 b"x48 8B ?? ?? ?? ?? E8\0Signature-Input\0bad root signature\0Open the scanner\0"
                 b".?AVScannerMenu@made@@\0.?AVpattern_formatter@spdlog@@\0")
        r = self.judge("Claim.dll", address=1, structure=1, extra=extra)
        self.assertEqual(r["signature_scan_evidence"], [])
        self.assertEqual(r["how"], NO_SIGNS_HOW + "; no game structures")
        self.assertEqual((r["verdict"], r["reason"]), (dlls.MAY_FAIL, NO_SIGNS_WHY))
        self.assertEqual(r["what_to_do"], NO_SIGNS_TODO)  # not "the code it searches for"
        # With Address Library too, the claim is still called unbacked, and the verdict is Address Library's.
        r = self.judge("Both.dll", address=5, structure=8)
        self.assertEqual(r["how"], "Address Library, " + NO_SIGNS_HOW + "; 1.14.70+ structure layout")
        self.assertEqual(r["verdict"], dlls.WORKS)

    def test_other_flags_unchanged(self):
        for address, how in ((0, "fixed addresses"), (4, "Address Library")):
            r = self.judge(f"F{address}.dll", address=address, structure=8, compatible=[V300],
                           extra=b"\x0048 8B ?? ?? ?? ?? E8\0")
            self.assertIsNone(r["signature_scan_evidence"])  # not looked for
            self.assertEqual(r["how"], how + "; 1.14.70+ structure layout")
        write(self.p("H.dll"), mk.pe_file(extra=b"\x0048 8B ?? ?? ?? ?? E8\0"))
        helper = dlls.judge(dlls.Item("H.dll", self.p("H.dll")), (1, 16, 300), True, None)
        self.assertNotIn("signature_scan_evidence", helper)  # not an SFSE plugin: no version data to check
        # verdict() without evidence (as other callers use it) keeps the old reason.
        block = pe.sfse_block(mk.sfse_plugin(address=1, structure=1))
        self.assertEqual(dlls.verdict(block, (1, 16, 300), True), (dlls.MAY_FAIL, "version independent by signature "
                                                                                   "scans"))

    def test_report_log_verdict_and_exit(self):
        folder = self.p("Plugins")
        write(os.path.join(folder, "Claim.dll"), mk.sfse_plugin(name="Claim", address=1, structure=1))
        logf = self.p("run.log")
        code, out = run("dlls", "--game-version", "1.16.300", folder, "--log", logf)
        self.assertEqual(code, 1)  # MAY FAIL, as before
        self.assertIn(f"    'Claim' by Test Author, plugin version 1; {NO_SIGNS_HOW}; no game structures\n", out)
        self.assertIn(f"    why: {NO_SIGNS_WHY}\n    what to do: {NO_SIGNS_TODO}\n", out)
        with open(logf, encoding="utf-8") as f:
            self.assertIn("[hints] Claim.dll: version data says signature scans; pattern-scan signs: none", f.read())
        write(os.path.join(folder, "Claim.dll"), mk.sfse_plugin(name="Claim", address=1, structure=1,
                                                                extra=b"\0sigscan\0"))
        code2, out2 = run("dlls", "--json", "--game-version", "1.16.300", folder)
        self.assertEqual(code2, code)
        r = json.loads(out2)["plugins"][0]
        self.assertEqual((r["verdict"], r["signature_scan_evidence"]), (dlls.MAY_FAIL, ["scanner text: sigscan"]))


# ---- framework hints for DLLs that can't be placed (all made up) ----------------------------------------------------
HINT_TEXT = (b"\0.?AVlogger@spdlog@@\0.?AVformat_error@v10@fmt@@\0.?AVtable@v3@toml@@\0.?AVmade@mylib@@\0"
             b".?AVITaskDelegate@SFSETaskInterface@@\0.?AUSFSEMadeUpInterface@@\0"
             b"Made Address Library file is for another game version: \0"
             b"Only game version 9.9.9 runs this made-up plugin\0")
HINT_LINE = ('    framework hints: libraries spdlog, fmt, toml (CommonLibSF plugins use spdlog and fmt, but so do '
             'others); SFSE plugin API types (SFSETaskInterface); its own Address Library reader text: "Made Address '
             'Library file is for another game version: "; its own game version check text: "Only game version '
             '9.9.9 runs this made-up plugin"')


class TestFrameworkHints(Temp):
    judge, one = TestFramework.judge, TestFramework.one

    def test_each_part(self):
        r = self.one("Hints.dll", mk.sfse_plugin(compatible=[V300], extra=HINT_TEXT))
        self.assertEqual(r["framework"], "can't tell")
        self.assertEqual(r["framework_hints"], {
            "libraries": ["spdlog", "fmt", "toml"], "sfse_api_types": ["SFSETaskInterface"],
            "address_library_text": ["Made Address Library file is for another game version: "],
            "version_check_text": ["Only game version 9.9.9 runs this made-up plugin"]})
        self.assertEqual(hints.hints_line(r["framework_hints"]), HINT_LINE)
        # Without spdlog or fmt there is no note; parts with nothing are left out.
        r = self.one("Boost.dll", mk.sfse_plugin(extra=b"\0.?AVerror@json@boost@@\0"))
        self.assertEqual(hints.hints_line(r["framework_hints"]), "    framework hints: libraries boost")

    def test_quotes_escaped_cut_and_capped(self):
        long = b"Only game version 1 is supported, " + b"x" * 100
        extra = (b"\0Address Library \x1b[2J\"wrong\" \\x41 file\0" + long + b"\0versionlib two\0addresslib three\0"
                 b"versionlib two\0")
        r = self.one("Odd.dll", mk.sfse_plugin(extra=extra))
        h = r["framework_hints"]
        # The file's own backslash is escaped too, so its text can't pass for this escaping (code-review round 2).
        self.assertEqual(h["address_library_text"],
                         ["Address Library \\x1b[2J\\x22wrong\\x22 \\x5cx41 file", "versionlib two"])
        self.assertEqual(h["version_check_text"], [long[:80].decode("ascii") + "..."])
        line = hints.hints_line(h)
        self.assertNotIn("\x1b", line)
        self.assertNotIn("addresslib three", line)  # up to 2 quotes each
        # A word past the cut moves the cut so the word stays in view.
        far = "class made::Thing<" + "x" * 150 + ">::ReadAddressLibrary(void) " + "y" * 60
        r = self.one("Far.dll", mk.sfse_plugin(extra=b"\0" + far.encode("ascii") + b"\0"))
        q = r["framework_hints"]["address_library_text"][0]
        self.assertTrue(q.startswith("...") and q.endswith("...") and "AddressLibrary" in q, q)
        self.assertEqual(len(q), 86)

    def test_only_for_cant_tell(self):
        for name, extra, pdb in (("Clsf.dll", mk.COMMONLIBSF_TEXT, None), ("Plain.dll", mk.PLAIN_SFSE_TEXT, None),
                                 ("Sym.dll", b"", mk.CLSF_PDB_TEXT)):  # the PDB places it: no hints
            r = self.one(name, mk.sfse_plugin(extra=extra + HINT_TEXT), pdb=pdb)
            self.assertNotEqual(r["framework"], "can't tell", name)
            self.assertNotIn("framework_hints", r, name)
        folder = self.p("Plugins")
        write(os.path.join(folder, "Helper.dll"), mk.pe_file(extra=HINT_TEXT))
        code, out = run("dlls", "--game-version", "1.16.300", folder)
        self.assertEqual(out.count("framework hints:"), 0, out)  # CommonLibSF, plain SFSE and a helper DLL

    def test_none_found(self):
        r = self.one("Bare.dll", mk.sfse_plugin())
        self.assertEqual(r["framework_hints"], {"libraries": [], "sfse_api_types": [], "address_library_text": [],
                                                "version_check_text": []})
        self.assertEqual(hints.hints_line(r["framework_hints"]),
                         "    framework hints: none (a stripped or packed DLL leaves none)")

    def test_report_counts_log_and_exit(self):
        folder = self.p("Plugins")
        write(os.path.join(folder, "Clsf.dll"), mk.sfse_plugin(compatible=[V300], extra=mk.COMMONLIBSF_TEXT))
        write(os.path.join(folder, "Hints.dll"), mk.sfse_plugin(compatible=[V300], extra=HINT_TEXT))
        write(os.path.join(folder, "Bare.dll"), mk.sfse_plugin(compatible=[V300]))
        logf = self.p("run.log")
        code, out = run("dlls", "--game-version", "1.16.300", folder, "--log", logf)
        self.assertEqual(code, 0)  # hints are evidence, not a verdict
        self.assertIn("Address Library: yes (Address Library text)\n" + HINT_LINE + "\n    risk evidence", out)
        self.assertIn("Frameworks: CommonLibSF 1, plain SFSE 0, can't tell 2\n", out)  # the counts don't change
        with open(logf, encoding="utf-8") as f:
            self.assertIn("[hints] Hints.dll: 6 type names; libraries ['spdlog', 'fmt', 'toml']; SFSE API types "
                          "['SFSETaskInterface'] (1 other SFSE type names); 1 Address Library reader and 1 game "
                          "version check messages", f.read())
        rep = json.loads(run("dlls", "--json", "--game-version", "1.16.300", folder)[1])
        self.assertEqual(rep["frameworks"], {"CommonLibSF": 1, "plain SFSE": 0, "can't tell": 2})
        self.assertEqual({r["file"] for r in rep["plugins"] if "framework_hints" in r}, {"Hints.dll", "Bare.dll"})


# ---- drift ------------------------------------------------------------------------------------------------------
def master_esm(stages=(10, 20), conditions=(1, 2), glob_value=1.0, compress=False, extra_quest=False):
    quests = [mk.quest(0x01000800, "TM_Quest", stages, compress=compress)]
    if extra_quest:
        quests.append(mk.quest(0x01000900, "TM_NewQuest", [5]))
    return mk.plugin(0x1, ["Starfield.esm"], [
        mk.group("QUST", quests),
        mk.group("CNDF", [mk.cndf(0x01000801, "TM_Start", conditions)]),
        mk.group("GLOB", [mk.glob(0x01000802, "TM_Glob", glob_value)]),
    ])


class TestDrift(Temp):
    def setUp(self):
        super().setUp()
        self.data = self.p("Data")
        write(self.p("Data", "Starfield.esm"), mk.plugin(0x1))
        write(self.p("Data", "TestMaster.esm"), master_esm())
        write(self.p("Data", "LightMaster.esm"), mk.plugin(0x101, ["Starfield.esm"],
                                                           [mk.group("GLOB", [mk.glob(0x01000801, "LM_Glob", 0)])]))
        self.mods = self.p("mods.json")
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"mod": "TestMod.esm", "masters": {"TestMaster.esm": {"records": [
                {"edid": "TM_Start", "copied": True, "why": "made-up start conditions"},
                {"edid": "TM_Quest", "stages": [10]}]}}}, f)
        self.base = self.p("baseline.json")

    def snap(self):
        self.assertEqual(run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)[0], 0)

    def check(self):
        return run("drift", "check", "--mods", self.mods, "--baseline", self.base, "--data", self.data)

    def test_unchanged(self):
        self.snap()
        code, out = self.check()
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: no change", out)

    def test_change_not_used(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), master_esm(glob_value=2.0, extra_quest=True))
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("UPDATED", out)

    def test_copied_record_changed(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), master_esm(conditions=(1, 3)))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("TM_Start: CHANGED", out)

    def test_stage_gone_and_compressed(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), master_esm(stages=(20, 30), compress=True))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("stage 10 is GONE", out)

    def test_record_gone(self):
        self.snap()
        write(self.p("Data", "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
            mk.quest(0x01000800, "TM_Quest", [10, 20])])]))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("TM_Start: GONE", out)

    def test_findings_and_snapshot_lines_escaped(self):
        """(0.5.2) Text from the mods file reaches drift's report lines: a right-to-left override, a line separator,
        an ESC or a newline in it is shown escaped, so it can't reorder a line, rewrite the terminal or fake a
        RESULT line."""
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"mod": "TestMod.esm", "masters": {"TestMaster.esm": {"records": [
                {"edid": "TM_Start", "copied": True, "why": "made\u202eup\u2028\x1b[2J\nRESULT: no change"},
                {"edid": "TM_Quest", "stages": [10]}, {"edid": "Made\u202eMissing"}]}}}, f)
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("1 not found: Made\\u202eMissing)", out)
        self.assertNotIn("\u202e", out)
        write(self.p("Data", "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
            mk.quest(0x01000800, "TM_Quest", [10, 20])])]))
        code, out = self.check()
        self.assertEqual(code, 2, out)
        self.assertIn("TM_Start: GONE (TestMod.esm: made\\u202eup\\u2028\\x1b[2J\\x0aRESULT: no change)", out)
        self.assertIn("Made\\u202eMissing: not found now or in the baseline", out)
        for ch in ("\u202e", "\u2028", "\x1b"):
            self.assertNotIn(ch, out)
        self.assertEqual(len([ln for ln in out.splitlines() if ln.startswith("RESULT:")]), 1)
        # --json keeps the raw text (JSON escapes it itself).
        code, out = run("drift", "check", "--mods", self.mods, "--baseline", self.base, "--data", self.data, "--json")
        self.assertNotIn("\u202e", out)
        self.assertTrue(any("made\u202eup\u2028\x1b[2J\nRESULT: no change" in f["text"]
                            for f in json.loads(out)["findings"]), out)

    def test_master_missing_and_bad_files(self):
        self.snap()
        os.remove(self.p("Data", "TestMaster.esm"))
        code, out = self.check()
        self.assertEqual(code, 3, out)
        self.assertIn("--plugin-dir", out)
        with open(self.mods, "w", encoding="utf-8") as f:
            f.write('{"masters": {"Data/TestMaster.esm": {"records": [{"stages": "ten"}]}}}')
        code, out = self.check()
        self.assertEqual(code, 3)
        self.assertIn("doesn't follow the mods file format:\n  ", out)  # one problem per line, as before
        self.assertIn("\nFix: see the README section 'The mods file'", out)
        with open(self.mods, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertIn("isn't valid JSON", self.check()[1])

    def test_plugin_dir_first(self):
        mm = self.p("MO2", "mods", "Test Master")
        write(os.path.join(mm, "TestMaster.esm"), master_esm(conditions=(9,)))
        self.snap()
        code, out = run("drift", "check", "--mods", self.mods, "--baseline", self.base, "--data", self.data,
                        "--plugin-dir", mm)
        self.assertEqual(code, 2, out)  # the mod manager's copy is read first, and it differs

    def test_never_writes_in_game_folder(self):
        game = self.p("Game")
        write(os.path.join(game, "Starfield.exe"), mk.pe_file(file_version=(1, 16, 300, 0)))
        write(os.path.join(game, "Data", "TestMaster.esm"), master_esm())
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", os.path.join(game, "b.json"), "--data",
                        os.path.join(game, "Data"))
        self.assertEqual(code, 3)
        self.assertIn("never writes there", out)
        self.assertFalse(os.path.exists(os.path.join(game, "b.json")))

    def test_init(self):
        mod = self.p("src", "TestMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm", "LightMaster.esm"], [
            mk.group("CNDF", [mk.cndf(0x01000801, "TM_Start", [1])]),         # override of TestMaster's record
            mk.group("GLOB", [mk.glob(0xFE000801, "LM_Glob", 5)]),            # override in a light master
            mk.group("KYWD", [mk.record("KYWD", 0x02000800, [mk.edid("TMod_Own")])]),  # the mod's own record
            mk.group("CELL", [mk.record("REFR", 0x01000999, [])]),            # a placed reference, no Editor ID
        ]))
        out_file = self.p("src", "mods.json")
        code, out = run("drift", "init", mod, "-o", out_file, "--data", self.data)
        self.assertEqual(code, 0, out)
        with open(out_file, encoding="utf-8") as f:
            m = json.load(f)
        self.assertEqual([r["edid"] for r in m["masters"]["TestMaster.esm"]["records"]], ["TM_Start"])
        self.assertEqual([r["edid"] for r in m["masters"]["LightMaster.esm"]["records"]], ["LM_Glob"])
        self.assertIn("1 REFR", out)
        self.assertEqual(run("drift", "init", mod, "-o", out_file, "--data", self.data)[0], 3)  # exists, no --force
        # The written file is a valid mods file, and every record has a type (fast scanning).
        self.assertEqual(drift.validate_mods(m), [])
        self.assertEqual(schema_problems(m), [])
        self.snap()

    def test_init_with_nothing_to_watch(self):
        # Found in the 0.1.3 clean-folder test: a plugin with only its own records gives an empty mods file. init
        # must say snapshot needs an entry first, and snapshot's refusal must name the cause, not a format error.
        mod = self.p("src", "OwnOnly.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm"],
                             [mk.group("KYWD", [mk.record("KYWD", 0x01000800, [mk.edid("Own_Kw")])])]))
        out_file = self.p("src", "mods.json")
        code, out = run("drift", "init", mod, "-o", out_file, "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("has nothing to watch yet", out)
        self.assertNotIn("Next: add the quest stages", out)  # not the line that sends you straight to snapshot
        code, out = run("drift", "snapshot", "--mods", out_file, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3)
        self.assertIn('"masters" is empty, so there is nothing to watch', out)
        self.assertFalse(os.path.exists(self.base))
        # A file with no "masters" at all keeps the format message.
        self.assertIn("at least one plugin", drift.validate_mods({"mod": "x.esm"})[0])

    def test_fingerprint(self):
        code, out = run("fingerprint", "TestMaster.esm", "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("probe FormID 000802", out)  # the GLOB is the highest own probe-type record
        with Plugin(self.p("Data", "LightMaster.esm"), [self.data]) as p:
            self.assertEqual(p.mask, 0xFFF)

    def test_round3_fingerprint_finds_data_and_warns(self):
        """(0.5.3, Round 3 C3) A plugin outside Data still finds its masters in the game's Data folder (so a light
        master isn't counted as full), and a master that isn't found gets a WARNING line."""
        from unittest import mock
        mod = self.p("src", "OutMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "LightMaster.esm"], [
            mk.group("GLOB", [mk.glob(0x01000802, "OM_Glob", 0)])]))
        code, with_data = run("fingerprint", mod, "--data", self.data)
        self.assertEqual(code, 0, with_data)
        with mock.patch.object(paths, "find_game", return_value=(self.p(), "found automatically")):
            code, auto = run("fingerprint", mod)
        self.assertEqual(code, 0, auto)
        self.assertEqual(auto, with_data)
        self.assertNotIn("WARNING", auto)
        with mock.patch.object(paths, "find_game", return_value=(None, [])):
            code, blind = run("fingerprint", mod)
        self.assertEqual(code, 0, blind)
        self.assertIn("LightMaster.esm", blind)
        self.assertIn("WARNING: these masters weren", blind)

    def test_round3_drift_check_baseline_first(self):
        """(0.5.3, Round 3 C4 and C5) A missing baseline is reported before any master is read, and a damaged
        master entry in a baseline is a CANNOT CHECK that names the file, not a KeyError."""
        from unittest import mock
        with mock.patch.object(drift, "take", side_effect=AssertionError("scanned before the baseline was read")):
            code, out = self.check()
        self.assertEqual(code, 3, out)
        self.assertIn("can't read the baseline", out)
        self.snap()
        with open(self.base, encoding="utf-8") as f:
            base = json.load(f)
        base["masters"]["TestMaster.esm"] = {}
        with open(self.base, "w", encoding="utf-8") as f:
            json.dump(base, f)
        code, out = self.check()
        self.assertEqual(code, 3, out)
        self.assertNotIn("KeyError", out)
        self.assertIn("TestMaster.esm", out)
        self.assertIn("run drift snapshot again", out)

    def test_init_and_fingerprint_lines_escaped(self):
        """(0.5.2 code-review round 1) Master names from a plugin header and a plugin's file name reach drift
        init's and fingerprint's lines: an ESC or newline in them (one byte per character in a header) or a
        right-to-left override (in a file name) is shown escaped."""
        mod = self.p("src", "Test\u202eMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm", "Ghost\x1b[2J\nRESULT: Master.esm"], [
            mk.group("CNDF", [mk.cndf(0x01000801, "TM_Start", [1])])]))
        code, out = run("drift", "init", mod, "-o", self.p("src", "mods.json"), "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("Ghost\\x1b[2J\\x0aRESULT: Master.esm", out)  # the "masters not found" note
        self.assertIn("  TestMaster.esm: 1 record(s)", out)
        self.assertNotIn("\x1b", out)
        self.assertFalse(any(ln.startswith("RESULT:") for ln in out.splitlines()), out)
        code, out = run("fingerprint", mod, "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("Test\\u202eMod.esm: probe FormID", out)
        self.assertNotIn("\u202e", out)

    def test_stage_never_there_is_a_note(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"records": [{"edid": "TM_Quest", "stages": [10, 99]}]}}}, f)
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("not found (check the name): TM_Quest stage 99", out)  # said at snapshot time, too
        write(self.p("Data", "TestMaster.esm"), master_esm(glob_value=2.0))
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("stage 99 not found now or in the baseline", out)

    def test_lower_case_type_and_used_by(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"used_by": ["MyMod"], "records": [
                {"edid": "tm_quest", "type": "qust"}]}}}, f)
        self.snap()
        with open(self.base, encoding="utf-8") as f:
            self.assertIsNotNone(json.load(f)["masters"]["TestMaster.esm"]["records"]["tm_quest"])
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"used_by": "MyMod", "records": []}}}, f)
        code, out = self.check()
        self.assertEqual(code, 3)
        self.assertIn("used_by must be a list", out)

    def test_snapshot_keeps_the_old_baseline(self):
        self.snap()
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3)
        self.assertIn("--force", out)
        self.assertEqual(run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data,
                             "--force")[0], 0)

    def test_damaged_record(self):
        for size_field in (b"\x01\x00", b"\x01\x00\x00\x00\x00\x00"):  # too short and too long
            write(self.p("Data", "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("CNDF", [
                mk.record("CNDF", 0x01000801, [mk.edid("TM_Start"), mk.sub("XXXX", size_field)])])]))
            code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
            self.assertEqual(code, 3, out)
            self.assertIn("TM_Start", out)
            self.assertIn("damaged XXXX", out)
            self.assertNotIn("unexpected error", out)

    def test_damaged_header_names_the_file(self):
        bad = mk.record("TES4", 0, [mk.sub("HEDR", bytes(12)), mk.sub("XXXX", b"\x01\x00")], flags=1)
        write(self.p("Data", "TestMaster.esm"), bad)
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3, out)
        self.assertIn("TestMaster.esm: a record has a damaged XXXX", out)
        write(self.p("Data", "TestMaster.esm"), b"just some text, not a plugin")
        code, out = run("drift", "snapshot", "--mods", self.mods, "-o", self.base, "--data", self.data)
        self.assertEqual(code, 3, out)
        self.assertIn("not a Starfield plugin", out)
        self.assertEqual(out.count("TestMaster.esm"), 1, out)  # the path is named once

    def test_file_names_ignore_case(self):
        from sf_patch_day import plugin as plugin_module
        folder = self.p("CaseTest")
        write(os.path.join(folder, "foo.ESM"), mk.plugin(0x1))
        plugin_module.clear_cache()
        found = plugin_module.find_plugin("Foo.esm", [folder])
        self.assertIsNotNone(found)
        self.assertEqual(os.path.basename(found).lower(), "foo.esm")
        exact = os.path.join(folder, "Bar.esm")
        write(exact, mk.plugin(0x1))
        self.assertEqual(plugin_module.find_plugin("Bar.esm", [folder]), exact)  # the exact name comes first
        self.assertIsNone(plugin_module.find_plugin("Missing.esm", [folder]))

    def test_case_fallback_on_a_case_sensitive_system(self):
        """Runs the fallback on any system: the file checks and the folder listing act as on Linux, where
        Foo.ESM and foo.ESM are two files and neither is Foo.esm."""
        from unittest import mock
        from sf_patch_day import log, plugin as plugin_module
        folder = os.path.abspath(self.p("CaseSensitive"))
        os.makedirs(folder)
        logf = self.p("case.log")
        log.setup(False, logf)  # opened before the file functions are replaced
        stored = {"foo.ESM", "Foo.ESM", "Bar.esm", "bar.ESM"}
        real_isfile, real_listdir = os.path.isfile, os.listdir
        fail_once = [True]

        def isfile(p):
            if os.path.normcase(os.path.dirname(p)) == os.path.normcase(folder):
                return os.path.basename(p) in stored
            return real_isfile(p)

        def listdir(d):
            if os.path.normcase(os.path.abspath(d)) == os.path.normcase(folder):
                if fail_once[0]:
                    fail_once[0] = False
                    raise PermissionError(13, "Access is denied", d)
                return sorted(stored)
            return real_listdir(d)
        key = os.path.normcase(folder)
        try:
            with mock.patch.object(plugin_module.os.path, "isfile", isfile), \
                    mock.patch.object(plugin_module.os, "listdir", listdir):
                plugin_module.clear_cache()
                self.assertIsNone(plugin_module.find_plugin("foo.esm", [folder]))  # the listing failed this once
                self.assertNotIn(key, plugin_module._INDEX)                         # and the failure isn't kept
                found = plugin_module.find_plugin("foo.esm", [folder + os.sep])     # the next lookup lists again
                self.assertEqual(os.path.basename(found), "Foo.ESM")                 # sorted: same pick every run
                self.assertIn(key, plugin_module._INDEX)
                plugin_module.find_plugin("foo.esm", [folder])                      # said once, not twice
                # An exact hit warns too when another copy differs only in case.
                self.assertEqual(plugin_module.find_plugin("Bar.esm", [folder]), os.path.join(folder, "Bar.esm"))
                warnings = plugin_module.warnings()
        finally:
            plugin_module.clear_cache()
            log.close()
        self.assertEqual(len(warnings), 2, warnings)
        self.assertIn("foo.ESM", warnings[0])
        self.assertIn("bar.ESM", warnings[1])
        self.assertIn("may load a different one", warnings[1])
        with open(logf, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("can't list", text)
        self.assertEqual(text.count("WARNING:"), 2, text)

    def test_bare_plugin_name_uses_the_current_folder(self):
        from sf_patch_day import plugin as plugin_module
        folder = self.p("BareName")
        # The master isn't there, so the lookup lists the plugin's own folder: for a bare name that is "", which
        # must mean the current folder (listing "" fails).
        write(os.path.join(folder, "Mod.esm"), mk.plugin(0x1, ["Starfield.esm"]))
        logf = self.p("bare.log")
        here = os.getcwd()
        os.chdir(folder)
        try:
            code, out = run("fingerprint", "Mod.esm", "--log", logf)
        finally:
            os.chdir(here)
            plugin_module.clear_cache()
        self.assertEqual(code, 0, out)
        with open(logf, encoding="utf-8") as f:
            self.assertNotIn("can't list", f.read())

    def test_copies_warning_escaped(self):
        """(0.5.2) The case-copy WARNING line holds file names from a folder listing: shown escaped."""
        from sf_patch_day import plugin as plugin_module
        plugin_module.clear_cache()
        plugin_module.WARNINGS.append(("k", "two copies: Mod\u202emse.esm, mod\x1b[2J\nRESULT: no change.esm"))
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                cli.say_warnings()
        finally:
            plugin_module.clear_cache()
        self.assertEqual(out.getvalue(), "WARNING: two copies: Mod\\u202emse.esm, mod\\x1b[2J\\x0aRESULT: no "
                                         "change.esm\n")

    def test_failed_run_still_shows_the_copies_warning(self):
        """A damaged plugin with a second copy that differs only in case (as on Linux): init and check fail, and
        the warning that may explain it is shown, with --json too."""
        from unittest import mock
        from sf_patch_day import plugin as plugin_module
        folder = os.path.abspath(self.p("Copies"))
        damaged = os.path.join(folder, "Mod.esm")
        write(damaged, b"damaged")
        real_isfile = os.path.isfile

        def index(f):
            return {"mod.esm": ["Mod.esm", "mod.ESM"]} if os.path.normcase(f) == os.path.normcase(folder) else {}

        def isfile(p):
            if os.path.normcase(os.path.dirname(p)) == os.path.normcase(folder):
                return os.path.basename(p) in ("Mod.esm", "mod.ESM")
            return real_isfile(p)
        with mock.patch.object(plugin_module, "_folder_index", index), \
                mock.patch.object(plugin_module.os.path, "isfile", isfile):
            code, out = run("drift", "init", damaged, "-o", self.p("m.json"), "--data", self.data)
            self.assertEqual(code, 3, out)
            self.assertIn("WARNING:", out)
            self.assertIn("RESULT: CANNOT CHECK", out)
            with open(self.mods, "w", encoding="utf-8") as f:
                json.dump({"masters": {"Mod.esm": {"records": []}}}, f)
            with open(self.p("empty-baseline.json"), "w", encoding="utf-8") as f:
                json.dump({"masters": {}}, f)  # read first since 0.5.3, so the scan is what fails
            code, out = run("drift", "check", "--mods", self.mods, "--baseline", self.p("empty-baseline.json"),
                            "--data", folder, "--json")
            self.assertEqual(code, 3, out)
            self.assertIn("WARNING:", out)
        # The --json setting never carries into a later run, also when a run stops early (an unwritable log).
        code, out = run("dlls", "--json", "--game-version", "1.16.300", self.p("nothing.dll"))
        self.assertEqual((code, json.loads(out)["exit"]), (3, 3))  # a JSON report that says exit 3
        self.assertFalse(cli._JSON[0])
        code, out = run("dlls", "--json", "--game-version", "1.16.300", "--log", self.p("no-such-folder", "x.log"))
        self.assertEqual(code, 3, out)
        self.assertIn("can't write the log file", out)  # the early stop, in plain text
        self.assertFalse(cli._JSON[0])
        # The next run without --json in the same process prints its text report, not JSON.
        code, out = run("dlls", "--game-version", "1.16.300", self.p("nothing.dll"))
        self.assertEqual(code, 3, out)
        self.assertIn("RESULT:", out)
        with self.assertRaises(ValueError):
            json.loads(out)

    def test_no_command_and_failed_log_setup(self):
        def run_err(*argv):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(list(argv))
            return code, out.getvalue(), err.getvalue()
        code, out, err = run_err()
        self.assertEqual(code, 3)
        self.assertIn("usage:", out)  # the help
        self.assertIn("RESULT: CANNOT CHECK: no command given", err)
        code, out, err = run_err("dlls", "--verbose", "--game-version", "1.16.300",
                                 "--log", self.p("no-such-folder", "x.log"))
        self.assertEqual(code, 3)
        self.assertIn("can't write the log file", out)
        self.assertNotIn("[end]", err)  # the log never opened, so it has no last line
        # drift without a step: help and a RESULT line on stderr, not an "unexpected error".
        code, out, err = run_err("drift")
        self.assertEqual(code, 3)
        self.assertIn("usage:", out)
        self.assertIn("RESULT: CANNOT CHECK: no drift step given", err)
        self.assertNotIn("unexpected error", out + err)
        # cmd_drift handles a bare "drift" itself too, without relying on main() to stop it first.
        args = cli.build_parser().parse_args(["drift"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.cmd_drift(args)
        self.assertEqual(code, 3)
        self.assertIn("usage:", out.getvalue())
        self.assertIn("RESULT: CANNOT CHECK: no drift step given", err.getvalue())
        # A hand-built Namespace with no "cmd" still gets the drift message, not "no command given".
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.cmd_drift(argparse.Namespace(drift_cmd=None))
        self.assertEqual(code, 3)
        self.assertIn("no drift step given", err.getvalue())
        # A run that stops on an error ends its log with that exit code, not "done".
        code, out, err = run_err("fingerprint", "x.esm", "--verbose", "--data", self.p("nowhere"))
        self.assertEqual(code, 3)
        self.assertIn("[end] exit code 3", err)

    def test_result_wording(self):
        self.assertEqual(drift.result([(drift.OK, "x")])[0], 0)
        code, res = drift.result([(drift.OK, "x"), (drift.WARN, "copies")])
        self.assertEqual(code, 1)
        self.assertIn("no change found, but see the WARN line", res)  # nothing changed: it mustn't say so
        code, res = drift.result([(drift.NOTE, "x"), (drift.WARN, "copies")])
        self.assertIn("NOTE lines", res)
        self.assertIn("also see the WARN line", res)  # the RESULT line alone tells the whole story
        self.assertIn("also see the WARN line", drift.result([(drift.SKIP, "x"), (drift.WARN, "copies")])[1])
        self.assertEqual(drift.result([(drift.ACTION, "x"), (drift.WARN, "copies")])[0], 2)

    def test_names_listed_twice(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"records": [{"edid": "TM_Quest"}, {"edid": "tm_quest"}]},
                                   "testmaster.esm": {"records": []}}}, f)
        code, out = self.check()
        self.assertEqual(code, 3)
        self.assertIn('"testmaster.esm" is listed twice', out)
        self.assertIn('record "tm_quest" is listed twice', out)

    def test_name_case_fixed_after_snapshot(self):
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"testmaster.esm": {"records": [{"edid": "tm_start", "copied": True}]}}}, f)
        self.snap()
        with open(self.mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"records": [{"edid": "TM_Start", "copied": True}]}}}, f)
        write(self.p("Data", "TestMaster.esm"), master_esm(conditions=(1, 3)))
        code, out = self.check()
        self.assertEqual(code, 2, out)  # the change is still found under the corrected spelling
        self.assertIn("TM_Start: CHANGED", out)

    def test_skip_without_pex_tools(self):
        mods = drift.load_mods(self.mods)
        mods["masters"]["TestMaster.esm"]["ba2"] = "TestMaster - Main.ba2"
        mods["masters"]["TestMaster.esm"]["functions"] = {"scripts/X.pex": ["DoIt"]}
        base = drift.take(mods, [self.data], None, "sf-pex-tools not found")
        lines = drift.compare(base, base, mods)
        self.assertIn(drift.SKIP, [lv for lv, _ in lines])
        self.assertEqual(drift.result(lines)[0], 1)


TOOLS, _ = pextools.find(None)


@unittest.skipIf(TOOLS is None, "sf-pex-tools not found (set SF_PEX_TOOLS)")
class TestDriftFunctions(Temp):
    def test_functions(self):
        data = self.p("Data")
        write(os.path.join(data, "TestMaster.esm"), master_esm())
        shutil.copy(os.path.join(TOOLS.folder, "tests", "fixtures", "a1.ba2"), os.path.join(data, "TestMaster - Main.ba2"))
        mods, base = self.p("mods.json"), self.p("base.json")
        with open(mods, "w", encoding="utf-8") as f:
            json.dump({"masters": {"TestMaster.esm": {"ba2": "TestMaster - Main.ba2", "records": [], "functions": {
                "Scripts/SfPexToolsTest/Alpha.pex": ["AddMission", "Score", "trycount", "NoSuchFunction"],
                "scripts/SfPexToolsTest/Gone.pex": ["Nothing"]}}}}, f)
        code, out = run("drift", "snapshot", "--mods", mods, "-o", base, "--data", data, "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        self.assertIn('scripts not found (check the path and the "ba2" archive name): '
                      'scripts/SfPexToolsTest/Gone.pex', out)
        self.assertIn("function NoSuchFunction()", out)  # a likely typo, said at snapshot time
        with open(base, encoding="utf-8") as f:
            b = json.load(f)
        funcs = b["masters"]["TestMaster.esm"]["functions"]
        # trycount matches TryCount: Papyrus names ignore case.
        self.assertEqual(funcs["Scripts/SfPexToolsTest/Alpha.pex"], {"AddMission": 2, "Score": 3, "trycount": 0})
        self.assertIsNone(funcs["scripts/SfPexToolsTest/Gone.pex"])
        code, out = run("drift", "check", "--mods", mods, "--baseline", base, "--data", data,
                        "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 1, out)  # missing now and in the baseline: check the name, not a rebuild
        self.assertIn("NoSuchFunction() not found now or in the baseline", out)
        self.assertIn("Gone.pex: not in", out)
        # Pretend the update changed Score's arguments, and the archive lost a script and a function.
        funcs["Scripts/SfPexToolsTest/Alpha.pex"]["Score"] = 2
        funcs["Scripts/SfPexToolsTest/Alpha.pex"]["NoSuchFunction"] = 1
        funcs["scripts/SfPexToolsTest/Gone.pex"] = {"Nothing": 0}
        with open(base, "w", encoding="utf-8") as f:
            json.dump(b, f)
        code, out = run("drift", "check", "--mods", mods, "--baseline", base, "--data", data,
                        "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 2, out)
        self.assertIn("Score() now takes 3 arguments (was 2)", out)
        self.assertIn("function NoSuchFunction() is GONE", out)
        self.assertIn("Gone.pex: script GONE", out)
        self.assertEqual(run("drift", "check", "--mods", mods, "--baseline", base, "--data", data,
                             "--pex-tools", self.p("nowhere"))[0], 3)


# ---- drift init reads the mod's scripts --------------------------------------------------------------------------
class TestScriptParts(Temp):
    """The parts of the script reader that don't need sf-pex-tools."""

    def test_split_args(self):
        self.assertEqual(scripts.split_args("ident:SetStage, ident:q, ident:::t1, int:10"),
                         ["ident:SetStage", "ident:q", "ident:::t1", "int:10"])
        # A comma or quote inside a string doesn't split it.
        self.assertEqual(scripts.split_args("ident:x, str:'a, b', str:\"it's, ok\", None"),
                         ["ident:x", "str:'a, b'", "str:\"it's, ok\"", "None"])
        self.assertEqual(scripts.split_args(""), [])

    def test_vmad(self):
        field = mk.vmad([("SM:QuestScript", [
            ("TargetQuest", 1, 0x01000800), ("Label", 2, "x"), ("StageProp", 3, 20), ("Rate", 4, 1.5),
            ("On", 5, True), ("Pair", 7, [("A", 1, 0x01000801), ("B", 3, 2)]), ("Many", 11, [1, 2]),
            ("Names", 12, ["a", "b"]), ("Rows", 17, [[("C", 3, 1)], [("C", 3, 2)]]), ("After", 1, 0x02000801)]),
            ("Second", [("Q", 1, 7)])], tail=b"\x02\x00\x00")  # quest fragment data after the scripts is left alone
        found = scripts.vmad_scripts(field[6:])
        self.assertEqual(found, [("SM:QuestScript", {"targetquest": ("obj", 0x01000800), "stageprop": ("int", 20),
                                                     "after": ("obj", 0x02000801)}),
                                 ("Second", {"q": ("obj", 7)})])
        with self.assertRaises(scripts.ScriptError):
            scripts.vmad_scripts(field[6:][:20])  # cut off

    def test_vmad_variable_properties(self):
        # Type 6 (Variable) has no value bytes and 16 (array of Variable) only a count, as xEdit reads them; the
        # record's other properties are still read.
        field = mk.vmad([("SM:S", [("V", 6, None), ("Vs", 16, 0), ("After", 1, 0x01000800), ("N", 3, 5)])])
        self.assertEqual(scripts.vmad_scripts(field[6:]), [("SM:S", {"after": ("obj", 0x01000800), "n": ("int", 5)})])

    def test_vmad_quest_tail(self):
        tail = mk.quest_tail("Fragments:Quests:QF_A", [("Q", 1, 0x01000800), ("Many", 16, 0)],
                             fragments=[(10, "Fragments:Quests:QF_A", "Fragment_Stage_0010")],
                             aliases=[(0, [("SM:AliasScript", [("Q", 1, 0x01000801)])]), (1, [])])
        field = mk.vmad([("SM:QuestScript", [])], tail=tail)
        attached, extra, problem = scripts.vmad_parts(field[6:], "QUST")
        self.assertEqual(attached, [("SM:QuestScript", {})])
        self.assertEqual(extra, [("Fragments:Quests:QF_A", {"q": ("obj", 0x01000800)}, "fragment"),
                                 ("Fragments:Quests:QF_A", {}, "fragment"),
                                 ("SM:AliasScript", {"q": ("obj", 0x01000801)}, "alias")])
        self.assertIsNone(problem)
        # A damaged tail keeps the attached scripts and says why.
        attached, extra, problem = scripts.vmad_parts(field[6:-3], "QUST")
        self.assertEqual((attached, extra), ([("SM:QuestScript", {})], []))
        self.assertIn("ends early", problem)
        # No tail, and record types without a fragment section: nothing more.
        self.assertEqual(scripts.vmad_parts(mk.vmad([("A", [])])[6:], "QUST")[1:], ([], None))
        self.assertEqual(scripts.vmad_parts(field[6:], "ACTI")[1:], ([], None))

    def test_vmad_fragment_tails_of_other_records(self):
        # INFO, PACK, SCEN, PERK and TMLM: the fragment script entry is read by the same helper as a quest's. With a
        # name it has a status byte and properties. With an empty name, Mutagen writes the name only (as a quest's
        # fragment script always is) and xEdit reads a full entry: both layouts are read and end at the field's end.
        frags = [("TIF_A", "Fragment_Begin"), ("TIF_B", "Fragment_End")]
        for sig in ("INFO", "PACK", "SCEN", "PERK", "TMLM"):
            phases = [("SF_Phase", "Fragment_Phase_01")] if sig == "SCEN" else []
            names = [(n, {}, "fragment") for n, _ in frags + phases]
            for case, kw, want in (
                    ("named", {"script": "Fragments:X", "props": [("Q", 1, 0x01000800)]},
                     [("Fragments:X", {"q": ("obj", 0x01000800)}, "fragment")] + names),
                    ("empty, Mutagen", {}, names),
                    ("empty, xEdit", {"full_empty": True}, names)):
                with self.subTest(sig=sig, case=case):
                    tail = mk.fragment_tail(sig, fragments=frags, phases=phases, **kw)
                    field = mk.vmad([("SM:Attached", [])], tail=tail)[6:]
                    self.assertEqual(scripts.vmad_parts(field, sig), ([("SM:Attached", {})], want, None))
        # A quest alias script with an empty name, as Mutagen writes it: the alias after it is still read.
        tail = (b"\x03" + struct.pack("<H", 0) + mk._wstr("") + struct.pack("<H", 2)
                + struct.pack("<HhI", 0, 0, 0) + struct.pack("<HHH", 6, 2, 1) + mk._wstr("")
                + struct.pack("<HhI", 0, 1, 0) + struct.pack("<HHH", 6, 2, 1) + mk.script_entry("SM:AliasB", []))
        field = mk.vmad([], tail=tail)[6:]
        self.assertEqual(scripts.vmad_parts(field, "QUST"), ([], [("SM:AliasB", {}, "alias")], None))

    def test_fragment_flags_high_bits_are_ignored(self):
        # The flags byte of an INFO, PACK or SCEN fragment section is counted as xEdit counts it: the low 2 bits for
        # INFO and SCEN, the low 3 for PACK. A higher bit set by hand has no fragment, and the section still ends
        # at the field's end.
        for sig, frags, flags in (("INFO", [("TIF_A", "Fragment_Begin"), ("TIF_B", "Fragment_End")], 0x83),
                                  ("SCEN", [("SF_A", "Fragment_Begin"), ("SF_B", "Fragment_End")], 0x43),
                                  ("PACK", [("PF_A", "Fragment_Begin"), ("PF_B", "Fragment_End"),
                                            ("PF_C", "Fragment_Change")], 0x0F)):
            with self.subTest(sig=sig):
                tail = (b"\x03" + bytes([flags]) + mk._wstr("")
                        + b"".join(b"\x00" + mk._wstr(s) + mk._wstr(f) for s, f in frags))
                if sig == "SCEN":
                    tail += struct.pack("<H", 0)
                field = mk.vmad([("SM:Attached", [])], tail=tail)[6:]
                self.assertEqual(scripts.vmad_parts(field, sig),
                                 ([("SM:Attached", {})], [(s, {}, "fragment") for s, _ in frags], None))

    def test_fragment_layout_order_per_record_type(self):
        # A quest tries the name-only layout first; here its empty alias entry is a full one (as xEdit reads it),
        # followed by a named alias: the name-only reading doesn't fit, the full one does.
        alias = struct.pack("<HhI", 0, 0, 0) + struct.pack("<HHH", 6, 2, 1)
        tail = (b"\x03" + struct.pack("<H", 0) + mk._wstr("") + struct.pack("<H", 2)
                + alias + mk.script_entry("", []) + alias + mk.script_entry("SM:AliasB", []))
        self.assertEqual(scripts.vmad_parts(mk.vmad([], tail=tail)[6:], "QUST"), ([], [("SM:AliasB", {}, "alias")],
                                                                                   None))
        # PERK and TMLM try xEdit's full entry first. With a byte too many at the end neither layout ends at the
        # field's end; the preferred (full) reading is kept, which finds the fragment (name-only finds none).
        for sig in ("PERK", "TMLM"):
            with self.subTest(sig):
                tail = mk.fragment_tail(sig, fragments=[("TIF_A", "Fragment_A")], full_empty=True) + b"\x00"
                self.assertEqual(scripts.vmad_parts(mk.vmad([], tail=tail)[6:], sig),
                                 ([], [("TIF_A", {}, "fragment")], None))

    def test_ambiguous_fragment_layout_is_reported(self):
        # Both layouts end at the field's end with different results: the preferred one is kept and reported.
        tail = ambiguous_info_tail()
        for sig in ("INFO", "PACK", "SCEN"):
            with self.subTest(sig):
                field = mk.vmad([], tail=tail + (b"\x00\x00" if sig == "SCEN" else b""))[6:]
                seen = []
                self.assertEqual(scripts.vmad_parts(field, sig, seen), ([], [("TIF_A", {}, "fragment")], None))
                self.assertEqual(seen, ["full entry (as xEdit reads it)"])
        # Not ambiguous: the usual empty-name records of test_vmad_fragment_tails_of_other_records report nothing.
        for full_empty in (False, True):
            seen = []
            tail = mk.fragment_tail("INFO", fragments=[("TIF_A", "Fragment_Begin")], full_empty=full_empty)
            scripts.vmad_parts(mk.vmad([], tail=tail)[6:], "INFO", seen)
            self.assertEqual(seen, [])

    def test_quest_empty_fragment_name_is_not_read_twice(self):
        # Both layouts read a quest's empty fragment script name the same way (name only), so it doesn't call for
        # the second read of the ambiguity check. An empty alias script name still does.
        calls_made = []
        old = scripts._other_fits

        def counting(*a):
            calls_made.append(a[2])
            return old(*a)
        scripts._other_fits = counting
        try:
            frag = mk.quest_tail(fragments=[(10, "QF_A", "Fragment_Stage_0010")])[:-2]  # without the alias count
            bare_alias = struct.pack("<H", 1) + struct.pack("<HhI", 0, 1, 0) + struct.pack("<HHH", 6, 2, 1) + mk._wstr("")
            for tail, expected in ((frag + struct.pack("<H", 0), 0), (frag + bare_alias, 1)):
                calls_made.clear()
                field = mk.vmad([], tail=tail)[6:]
                seen = []
                self.assertEqual(scripts.vmad_parts(field, "QUST", seen)[0], [])
                self.assertEqual((len(calls_made), seen), (expected, []))
        finally:
            scripts._other_fits = old

    def test_console_archives_left_out(self):
        d = self.p("d")
        write(os.path.join(d, "MyMod - Main.ba2"), mk.ba2([]))
        write(os.path.join(d, "MyMod - Main_xbox.ba2"), mk.ba2([]))
        write(os.path.join(d, "MyMod - Main_PS5.ba2"), mk.ba2([]))
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("MyMod", [d])], ["MyMod - Main.ba2"])
        os.remove(os.path.join(d, "MyMod - Main.ba2"))  # only console archives: read them
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("MyMod", [d])],
                         ["MyMod - Main_PS5.ba2", "MyMod - Main_xbox.ba2"])

    def test_own_archives(self):
        d = self.p("d")
        write(os.path.join(d, "MyMod - Main.ba2"), mk.ba2([("scripts/a.pex", b"x")]))
        write(os.path.join(d, "MyMod - Textures.ba2"), b"BTDX\x01\x00\x00\x00DX10" + bytes(12))  # textures: no scripts
        write(os.path.join(d, "MyMod - Part - Main.ba2"), mk.ba2([]))  # belongs to "MyMod - Part.esm"
        write(os.path.join(d, "MyModOther - Main.ba2"), mk.ba2([]))
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("MyMod", [d])], ["MyMod - Main.ba2"])
        self.assertEqual([os.path.basename(p) for p in scripts.own_archives("mymod - part", [d])],
                         ["MyMod - Part - Main.ba2"])

    def test_init_without_pex_tools(self):
        data, mod = self.p("Data"), self.p("src", "ScriptMod.esm")
        write(os.path.join(data, "Starfield.esm"), mk.plugin(0x1))
        write(os.path.join(data, "TestMaster.esm"), master_esm())
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
            mk.group("QUST", [mk.record("QUST", 0x02000800, [mk.edid("SM_Quest"),
                                                             mk.vmad([("SM:QuestScript", [])])])])]))
        mods, notes, summary = drift.init(mod, [data], None, "sf-pex-tools not found (install it)")
        self.assertEqual(mods["masters"], {})  # as in 0.1.3: only overrides, and there are none
        self.assertTrue(any(n.startswith("scripts not read: sf-pex-tools not found (install it)") for n in notes),
                        notes)
        self.assertIsNone(summary["scripts"])


def script_mod(root, data):
    """A made-up mod in root (ScriptMod.esm, its archive and a loose script) whose scripts call functions of
    sf-pex-tools' made-up test scripts (in TestMaster - Main.ba2) and set stages of TestMaster.esm's TM_Quest."""
    write(os.path.join(data, "Starfield.esm"), mk.plugin(0x1))
    write(os.path.join(data, "TestMaster.esm"), master_esm(stages=(10, 20, 30)))
    shutil.copy(os.path.join(TOOLS.folder, "tests", "fixtures", "a1.ba2"), os.path.join(data, "TestMaster - Main.ba2"))
    quest = mk.pex("SM:QuestScript", "Quest",
                   variables=[("::TargetQuest_var", "Quest"), ("::StageProp_var", "Int"),
                              ("Helper", "SfPexToolsTest:Alpha"), ("Kid", "SM:Kid")],
                   properties=[("TargetQuest", "Quest", "::TargetQuest_var"), ("StageProp", "Int", "::StageProp_var")],
                   functions=[
                       ("Run", [], [("::t1", "Bool"), ("::t2", "Int"), ("::t3", "Float"), ("::t4", "String"),
                                    ("::nonevar", "None")], [
                           ("callmethod", ["ident:SetStage", "ident:::TargetQuest_var", "ident:::t1", "int:10"]),
                           ("callmethod", ["ident:Step", "ident:self", "ident:::nonevar", "ident:::TargetQuest_var",
                                           "ident:::StageProp_var"]),
                           ("callmethod", ["ident:AddMission", "ident:Helper", "ident:::t2", "str:a, b", "int:5"]),
                           ("callmethod", ["ident:score", "ident:Helper", "ident:::t3", "int:1"]),  # 1 of 3 arguments
                           ("callstatic", ["ident:SfPexToolsTest:Beta", "ident:Describe", "ident:::t4"]),
                           ("callmethod", ["ident:Vanished", "ident:Helper", "ident:::nonevar"]),
                           ("callmethod", ["ident:Note", "ident:Kid", "ident:::nonevar", "str:x"])]),
                       ("Step", [("akQuest", "Quest"), ("aiStage", "Int")], [("::t1", "Bool")], [
                           ("callmethod", ["ident:SetStage", "ident:akQuest", "ident:::t1", "ident:aiStage"])])])
    kid = mk.pex("SM:Kid", "SfPexToolsTest:Beta", functions=[
        ("Note", [("asName", "String")], [("::nonevar", "None"), ("::t1", "String")], [
            ("callparent", ["ident:Note", "ident:::nonevar", "ident:asName"]),
            ("callmethod", ["ident:Describe", "ident:self", "ident:::t1"])])])
    selfq = mk.pex("SM:SelfScript", "Quest", functions=[
        ("Go", [], [("::t1", "Bool"), ("x", "Int")], [
            ("callmethod", ["ident:SetStage", "ident:self", "ident:::t1", "int:20"]),
            ("callmethod", ["ident:SetCurrentStageID", "ident:self", "ident:::t1", "ident:x"])])])  # not known
    write(os.path.join(root, "ScriptMod - Main.ba2"), mk.ba2([("scripts/SM/QuestScript.pex", quest)]))
    write(os.path.join(root, "Scripts", "SM", "Kid.pex"), kid)  # loose, reached through QuestScript's variable
    write(os.path.join(root, "Scripts", "SM", "SelfScript.pex"), selfq)  # loose, attached to the override
    mod = os.path.join(root, "ScriptMod.esm")
    write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
        mk.group("QUST", [
            mk.record("QUST", 0x02000800, [mk.edid("SM_Quest"), mk.vmad([("SM:QuestScript", [
                ("TargetQuest", 1, 0x01000800), ("StageProp", 3, 30)])], tail=mk.quest_tail())]),
            # An override of TM_Quest with the mod's script attached: SetStage on self is TM_Quest.
            mk.record("QUST", 0x01000800, [mk.edid("TM_Quest"), mk.vmad([("SM:SelfScript", [])])])])]))
    return mod


def schema_problems(doc, schema=None, where="$"):
    """The ways doc breaks examples/mods.schema.json, checked with the parts of JSON Schema that file uses (the
    standard library has no JSON Schema checker)."""
    if schema is None:
        with open(os.path.join(os.path.dirname(HERE), "examples", "mods.schema.json"), encoding="utf-8") as f:
            schema = json.load(f)
    kinds = {"object": dict, "array": list, "string": str, "boolean": bool}
    t = schema.get("type")
    if t == "integer":
        if not isinstance(doc, int) or isinstance(doc, bool):
            return [f"{where}: not an integer"]
    elif t and not isinstance(doc, kinds[t]):
        return [f"{where}: not {t}"]
    p = []
    if isinstance(doc, (int, float)) and not isinstance(doc, bool):
        if doc < schema.get("minimum", doc) or doc > schema.get("maximum", doc):
            p.append(f"{where}: {doc} out of range")
    if isinstance(doc, str) and not schema.get("minLength", 0) <= len(doc) <= schema.get("maxLength", len(doc)):
        p.append(f"{where}: length {len(doc)}")
    if isinstance(doc, dict):
        p += [f"{where}: {k} missing" for k in schema.get("required", []) if k not in doc]
        if len(doc) < schema.get("minProperties", 0):
            p.append(f"{where}: too few entries")
        pattern = schema.get("propertyNames", {}).get("pattern")
        for k, v in doc.items():
            if pattern and not re.search(pattern, k):
                p.append(f"{where}: name {k!r} doesn't match {pattern}")
            sub = schema.get("properties", {}).get(k, schema.get("additionalProperties", {}))
            p += schema_problems(v, sub if isinstance(sub, dict) else {}, f"{where}.{k}")
    if isinstance(doc, list) and "items" in schema:
        for i, v in enumerate(doc):
            p += schema_problems(v, schema["items"], f"{where}[{i}]")
    return p


class TestSchema(unittest.TestCase):
    def test_example_and_checker(self):
        with open(os.path.join(os.path.dirname(HERE), "examples", "mods.example.json"), encoding="utf-8") as f:
            self.assertEqual(schema_problems(json.load(f)), [])
        self.assertTrue(schema_problems({"masters": {"bad/name.esm": {"records": [{"type": "QUSTX"}]}}}))


@unittest.skipIf(TOOLS is None, "sf-pex-tools not found (set SF_PEX_TOOLS)")
class TestInitScripts(Temp):
    def test_ambiguous_fragment_layout_is_a_note(self):
        # The mod's own INFO whose fragment section fits both layouts: init keeps the usual one (TIF_A is read as
        # the mod's fragment script), says so in a note, and logs it under --verbose.
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        mod = os.path.join(src, "ScriptMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
            mk.group("QUST", [mk.record("QUST", 0x01000800, [mk.edid("TM_Quest")])]),
            mk.group("INFO", [mk.record("INFO", 0x02000801, [mk.vmad([], tail=ambiguous_info_tail())])])]))
        write(os.path.join(src, "Scripts", "TIF_A.pex"), mk.pex("TIF_A", "TopicInfo"))
        log_file = self.p("init.log")
        code, out = run("drift", "init", mod, "-o", self.p("m.json"), "--data", data, "--pex-tools", TOOLS.folder,
                        "--log", log_file)
        self.assertEqual(code, 0, out)
        self.assertIn("note: the fragment scripts of 1 INFO record(s) can be read two ways; the full entry (as xEdit "
                      "reads it) layout was used, the usual one for INFO: 02000801\n", out)
        self.assertIn("read 1 of your mod's own script(s)", out)
        with open(log_file, encoding="utf-8") as f:
            self.assertIn("INFO 02000801: its fragment section reads two ways", f.read())

    def test_ambiguous_fragment_layout_note_is_one_line_per_type(self):
        # 22 such records: one note for the type, listing 20 FormIDs and "and 2 more" (the log has them all).
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        mod = os.path.join(src, "ScriptMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
            mk.group("QUST", [mk.record("QUST", 0x01000800, [mk.edid("TM_Quest")])]),
            mk.group("INFO", [mk.record("INFO", 0x02000801 + i, [mk.vmad([], tail=ambiguous_info_tail())])
                              for i in range(22)])]))
        write(os.path.join(src, "Scripts", "TIF_A.pex"), mk.pex("TIF_A", "TopicInfo"))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        lines = [n for n in notes if "read two ways" in n]
        listed = ", ".join(f"{0x02000801 + i:08X}" for i in range(20))
        self.assertEqual(lines, [f"the fragment scripts of 22 INFO record(s) can be read two ways; the full entry (as "
                                 f"xEdit reads it) layout was used, the usual one for INFO: {listed} and 2 more"])

    def test_init_reads_scripts(self):
        data, src = self.p("Data"), self.p("src")
        mod = script_mod(src, data)
        out_file = self.p("mods.json")
        code, out = run("drift", "init", mod, "-o", out_file, "--data", data, "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        with open(out_file, encoding="utf-8") as f:
            m = json.load(f)
        self.assertEqual(drift.validate_mods(m), [])
        self.assertEqual(schema_problems(m), [])
        self.assertEqual(list(m["masters"]), ["TestMaster.esm"])
        tm = m["masters"]["TestMaster.esm"]
        self.assertEqual(tm["ba2"], "TestMaster - Main.ba2")
        self.assertEqual(tm["functions"], {"scripts/sfpextoolstest/alpha.pex": ["AddMission", "Score"],
                                           "scripts/sfpextoolstest/beta.pex": ["Describe", "Note"]})
        # One record: the override, marked copied, with the stages both scripts set (10 constant, 30 from the Int
        # property through Step, 20 on self). SetCurrentStageID(x) can't be known before the game runs.
        self.assertEqual(len(tm["records"]), 1, tm["records"])
        rec = tm["records"][0]
        self.assertEqual((rec["edid"], rec["type"], rec["copied"], rec["stages"]), ("TM_Quest", "QUST", True, [10, 20, 30]))
        self.assertIn("SM:QuestScript, SM:SelfScript", rec["why"])
        self.assertIn("isn't listed", rec["why"])
        self.assertIn("Score() with 1 argument(s), but the installed TestMaster.esm script takes 3", out)
        self.assertIn("SfPexToolsTest:Alpha.Vanished(), which no master script defines now", out)
        self.assertIn("read 3 of your mod's own script(s)", out)
        self.assertNotIn("note: the fragment or alias scripts", out)
        # The file works with snapshot and check: every stage and function is found.
        base = self.p("base.json")
        code, out = run("drift", "snapshot", "--mods", out_file, "-o", base, "--data", data, "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        self.assertNotIn("not found (check the name)", out)
        self.assertIn("4 function(s)", out)
        code, out = run("drift", "check", "--mods", out_file, "--baseline", base, "--data", data,
                        "--pex-tools", TOOLS.folder)
        self.assertEqual(code, 0, out)
        # The same input gives the same file, byte for byte.
        again = self.p("again.json")
        self.assertEqual(run("drift", "init", mod, "-o", again, "--data", data, "--pex-tools", TOOLS.folder)[0], 0)
        with open(out_file, "rb") as a, open(again, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_new_quest_record_and_bad_pex(self):
        # A quest the mod doesn't override gets its own record; a damaged script is a note, not a failure.
        data, src = self.p("Data"), self.p("src")
        script_mod(src, data)
        selfq = mk.pex("SM:Setter", "Quest", variables=[("::Q_var", "Quest")], properties=[("Q", "Quest", "::Q_var")],
                       functions=[("Go", [], [("::t1", "Bool")], [
                           ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:10"])])])
        write(os.path.join(src, "Scripts", "SM", "Setter.pex"), selfq)
        write(os.path.join(src, "Scripts", "SM", "Broken.pex"), b"\xde\xc0\x57\xfa damaged")
        mod = os.path.join(src, "Other.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [mk.group("QUST", [
            mk.record("QUST", 0x02000800, [mk.edid("OT_Quest"), mk.vmad([("SM:Setter", [("Q", 1, 0x01000800)]),
                                                                           ("SM:Broken", [])])])])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        rec = mods["masters"]["TestMaster.esm"]["records"]
        self.assertEqual(rec, [{"edid": "TM_Quest", "type": "QUST", "why": "Stages set by script SM:Setter",
                                "stages": [10]}])
        self.assertEqual(summary["quests"], 1)
        self.assertTrue(any("couldn't read scripts/SM/Broken.pex" in n for n in notes), notes)

    def test_pex_tools_given_but_missing(self):
        data, src = self.p("Data"), self.p("src")
        mod = script_mod(src, data)
        code, out = run("drift", "init", mod, "-o", self.p("m.json"), "--data", data, "--pex-tools", self.p("nowhere"))
        self.assertEqual(code, 3)
        self.assertIn("ba2_extract.py and pex_compare.py aren't there", out)
        self.assertFalse(os.path.exists(self.p("m.json")))


def tm_world(data):
    """Starfield.esm, TestMaster.esm (TM_Quest, stages 10 20 30) and TestMaster - Main.ba2 holding the made-up
    scripts TM:Base (Hello()) and TM:Api extends TM:Base (Ping(aiValue), Pong())."""
    write(os.path.join(data, "Starfield.esm"), mk.plugin(0x1))
    write(os.path.join(data, "TestMaster.esm"), master_esm(stages=(10, 20, 30)))
    write(os.path.join(data, "TestMaster - Main.ba2"), mk.ba2([
        ("scripts/TM/Base.pex", tm_base()),
        ("scripts/TM/Api.pex", mk.pex("TM:Api", "TM:Base", functions=[("Ping", [("aiValue", "Int")], [], []),
                                                                       ("Pong", [], [], [])]))]))


def ambiguous_info_tail():
    """An INFO fragment section (one fragment) that fits both layouts. As xEdit reads it: an empty script entry
    (name, status, no properties), then the fragment TIF_A with a 1272-character function name. Name-only reads the
    status byte as the fragment's first byte, an empty script name, and a 1280-character function name that runs to
    the field's end (00 05 is 1280), so it finds no named fragment."""
    return mk.fragment_tail("INFO", fragments=[("TIF_A", "F" * 1272)], full_empty=True)


def tm_base():
    return mk.pex("TM:Base", "ScriptObject", functions=[("Hello", [], [], [])])


def calls(name, parent, *targets, variables=(), properties=(), code=()):
    """A made-up script whose Run() makes the static calls targets [(type, function, [args])] and runs code."""
    return mk.pex(name, parent, variables=variables, properties=properties, functions=[
        ("Run", [], [("::t", "None")], [("callstatic", [f"ident:{t}", f"ident:{f}", "ident:::t"] + list(a))
                                        for t, f, a in targets] + list(code))])


def init_lines(out):
    return [x for x in out.splitlines() if x.startswith("note:")]


@unittest.skipIf(TOOLS is None, "sf-pex-tools not found (set SF_PEX_TOOLS)")
class TestInitScriptOwnership(Temp):
    """Which copy of a script is the mod's own and which is a master's (the game's rules: a loose file beats every
    archive, a later archive beats an earlier one)."""

    def mod_plugin(self, path, masters=("Starfield.esm", "TestMaster.esm"), vmad=None):
        own = len(masters) << 24 | 0x800
        write(path, mk.plugin(0x1, list(masters), [mk.group("QUST", [
            mk.record("QUST", own, [mk.edid("SM_Quest"), vmad or mk.vmad([("SM:Main", [])])])])]))
        return path

    def test_mod_copy_of_a_master_script_is_the_mods_own(self):
        # The mod ships a changed TM:Api (Ping only), in its archive or loose. Its copy is the one the game runs:
        # Ping is the mod's own function, Hello (inherited from TM:Base) is still the master's, and the mod is
        # never listed as its own master.
        main = calls("SM:Main", "Quest", ("TM:Api", "Ping", ["int:1"]), ("TM:Api", "Hello", []))
        changed = mk.pex("TM:Api", "TM:Base", functions=[("Ping", [("aiValue", "Int")], [], [])])
        for how in ("archive", "loose"):
            with self.subTest(how):
                data, src = self.p(how, "Data"), self.p(how, "src")
                tm_world(data)
                files = [("scripts/SM/Main.pex", main)]
                if how == "archive":
                    files.append(("scripts/TM/Api.pex", changed))
                else:
                    write(os.path.join(src, "Scripts", "TM", "Api.pex"), changed)
                write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2(files))
                mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"))
                mods, notes, summary = drift.init(mod, [data], TOOLS)
                self.assertEqual(list(mods["masters"]), ["TestMaster.esm"], notes)
                self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]})
                self.assertEqual(summary["scripts"], 2)
                self.assertFalse([n for n in notes if "defines now" in n or "argument" in n], notes)

    def test_function_from_the_mods_copy_of_a_parent(self):
        # The mod ships a changed TM:Base with a new function Extra(); its call TM:Api.Extra() (TM:Api is the
        # master's, its parent TM:Base the mod's) is the mod's own function, not "no master script defines it".
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2([
            ("scripts/SM/Main.pex", calls("SM:Main", "Quest", ("TM:Api", "Extra", []), ("TM:Api", "Pong", []))),
            ("scripts/TM/Base.pex", mk.pex("TM:Base", "ScriptObject", functions=[("Hello", [], [], []),
                                                                                ("Extra", [], [], [])]))]))
        mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(list(mods["masters"]), ["TestMaster.esm"])
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Api.pex": ["Pong"]})
        self.assertFalse([n for n in notes if "defines now" in n], notes)

    def test_stage_above_65535_is_not_known(self):
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        write(os.path.join(src, "Scripts", "SM", "Main.pex"), mk.pex(
            "SM:Main", "Quest", variables=[("::Q_var", "Quest")], properties=[("Q", "Quest", "::Q_var")],
            functions=[("Go", [], [("::t1", "Bool")], [
                ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:70000"]),
                ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:-1"])])]))  # -1: no stage
        mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"), vmad=mk.vmad([("SM:Main", [("Q", 1, 0x01000800)])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        rec = mods["masters"]["TestMaster.esm"]["records"]
        self.assertEqual(len(rec), 1)
        self.assertNotIn("stages", rec[0])
        self.assertIn("isn't listed", rec[0]["why"])

    def test_master_attached_script_on_an_overridden_record(self):
        # TM:Starter (a master script that sets stage 20 on its own quest) on TM_Quest. When the master's copy of
        # TM_Quest already has it, the mod's override only keeps it: stage 20 is the master's doing. When the mod
        # added it to the record, or ships its own copy of TM:Starter, it's the mod's.
        starter = mk.pex("TM:Starter", "Quest", functions=[("Go", [], [("::t1", "Bool")], [
            ("callmethod", ["ident:SetStage", "ident:self", "ident:::t1", "int:20"])])])
        cases = {"kept from the master": (True, False, None),
                 "added by the mod": (False, False, [20]),
                 "the mod's own copy": (True, True, [20])}
        for name, (master_has, own_copy, stages) in cases.items():
            with self.subTest(name):
                data, src = self.p(name, "Data"), self.p(name, "src")
                tm_world(data)
                write(os.path.join(data, "TestMaster - Main.ba2"), mk.ba2([
                    ("scripts/TM/Base.pex", tm_base()), ("scripts/TM/Starter.pex", starter)]))
                tm_quest = [mk.edid("TM_Quest"), mk.sub("INDX", struct.pack("<HH", 10, 0)),
                            mk.sub("INDX", struct.pack("<HH", 20, 0))]
                write(os.path.join(data, "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, tm_quest + ([mk.vmad([("TM:Starter", [])])] if master_has else []))])]))
                if own_copy:
                    write(os.path.join(src, "Scripts", "TM", "Starter.pex"), starter)
                mod = os.path.join(src, "ScriptMod.esm")
                write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, [mk.edid("TM_Quest"), mk.vmad([("TM:Starter", [])])])])]))
                log_file = self.p(name, "init.log")
                code, out = run("drift", "init", mod, "-o", self.p(name, "m.json"), "--data", data,
                                "--pex-tools", TOOLS.folder, "--log", log_file)
                self.assertEqual(code, 0, out)
                with open(self.p(name, "m.json"), encoding="utf-8") as f:
                    rec = json.load(f)["masters"]["TestMaster.esm"]["records"]
                self.assertEqual([r["edid"] for r in rec], ["TM_Quest"], rec)
                self.assertEqual(rec[0].get("stages"), stages, rec)
                with open(log_file, encoding="utf-8") as f:
                    logged = f.read()
                if not own_copy:
                    self.assertIn("the master's copy of the record has it too" if master_has
                                  else "your mod added it to the record", logged)

    def test_master_attached_script_with_a_changed_property(self):
        # TM:Setter sets stage 20 on its Q property's quest. The master's TM_Quest has it with Q = TM_Quest. A mod
        # that keeps Q keeps the master's doing; one that points Q at TM_Other sets TM_Other's stage itself.
        setter = mk.pex("TM:Setter", "Quest", variables=[("::Q_var", "Quest")], properties=[("Q", "Quest", "::Q_var")],
                        functions=[("Go", [], [("::t1", "Bool")], [
                            ("callmethod", ["ident:SetStage", "ident:::Q_var", "ident:::t1", "int:20"])])])
        stages = [mk.sub("INDX", struct.pack("<HH", 10, 0)), mk.sub("INDX", struct.pack("<HH", 20, 0))]
        for name, q, expected in (("kept", 0x01000800, {"TM_Quest": None}),
                                  ("changed", 0x01000801, {"TM_Quest": None, "TM_Other": [20]})):
            with self.subTest(name):
                data, src = self.p(name, "Data"), self.p(name, "src")
                tm_world(data)
                write(os.path.join(data, "TestMaster - Main.ba2"), mk.ba2([
                    ("scripts/TM/Base.pex", tm_base()), ("scripts/TM/Setter.pex", setter)]))
                write(os.path.join(data, "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, [mk.edid("TM_Quest")] + stages
                              + [mk.vmad([("TM:Setter", [("Q", 1, 0x01000800)])])]),
                    mk.record("QUST", 0x01000801, [mk.edid("TM_Other")] + stages)])]))
                mod = os.path.join(src, "ScriptMod.esm")
                write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, [mk.edid("TM_Quest"), mk.vmad([("TM:Setter", [("Q", 1, q)])])])])]))
                log_file = self.p(name, "init.log")
                code, out = run("drift", "init", mod, "-o", self.p(name, "m.json"), "--data", data,
                                "--pex-tools", TOOLS.folder, "--log", log_file)
                self.assertEqual(code, 0, out)
                with open(self.p(name, "m.json"), encoding="utf-8") as f:
                    rec = json.load(f)["masters"]["TestMaster.esm"]["records"]
                self.assertEqual({r["edid"]: r.get("stages") for r in rec}, expected, rec)
                with open(log_file, encoding="utf-8") as f:
                    logged = f.read()
                self.assertIn("the master's copy of the record has it too" if name == "kept"
                              else "your mod changed its property q; its stages are credited", logged)

    def test_master_attached_script_when_a_later_master_cant_be_read(self):
        # TestMaster's TM_Quest has TM:Starter (stage 20). Later.esm, loaded after it, overrides TM_Quest with a
        # damaged record: its copy is the one the mod replaces, and it can't be read, so TestMaster's copy doesn't
        # decide and stage 20 is credited to the mod (0.2.0's behavior when it can't tell). The same when Later.esm
        # isn't installed. A damaged Later.esm that doesn't list TestMaster.esm as a master can't hold TM_Quest:
        # TestMaster's copy still decides.
        starter = mk.pex("TM:Starter", "Quest", functions=[("Go", [], [("::t1", "Bool")], [
            ("callmethod", ["ident:SetStage", "ident:self", "ident:::t1", "int:20"])])])
        damaged = b"\x40\x00\x00\x00" + b"not zlib data"
        cases = (("damaged", ["Starfield.esm", "TestMaster.esm"], [20], "the master's copy can't be read"),
                 ("not installed", None, [20], "Later.esm isn't installed and might hold the last copy"),
                 ("can't hold it", ["Starfield.esm"], None, "the master's copy of the record has it too"))
        for name, later_masters, stages, logged in cases:
            with self.subTest(name):
                data, src = self.p(name, "Data"), self.p(name, "src")
                tm_world(data)
                write(os.path.join(data, "TestMaster - Main.ba2"), mk.ba2([
                    ("scripts/TM/Base.pex", tm_base()), ("scripts/TM/Starter.pex", starter)]))
                quest = [mk.edid("TM_Quest"), mk.sub("INDX", struct.pack("<HH", 10, 0)),
                         mk.sub("INDX", struct.pack("<HH", 20, 0))]
                write(os.path.join(data, "TestMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, quest + [mk.vmad([("TM:Starter", [])])])])]))
                if later_masters:
                    # Holding TM_Quest: a copy that won't unpack. Not holding it: a group that runs past the end, so
                    # the walk itself fails.
                    bad = (mk.group("QUST", [b"QUST" + struct.pack("<III", len(damaged), 0x40000, 0x01000800)
                                             + bytes(8) + damaged])
                           if len(later_masters) == 2 else
                           b"GRUP" + struct.pack("<I", 5000) + b"QUST" + bytes(12))
                    write(os.path.join(data, "Later.esm"), mk.plugin(0x1, later_masters, [bad]))
                mod = os.path.join(src, "ScriptMod.esm")
                write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm", "Later.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, [mk.edid("TM_Quest"), mk.vmad([("TM:Starter", [])])])])]))
                log_file = self.p(name, "init.log")
                code, out = run("drift", "init", mod, "-o", self.p(name, "m.json"), "--data", data,
                                "--pex-tools", TOOLS.folder, "--log", log_file)
                self.assertEqual(code, 0, out)
                with open(self.p(name, "m.json"), encoding="utf-8") as f:
                    rec = json.load(f)["masters"]["TestMaster.esm"]["records"]
                self.assertEqual([(r["edid"], r.get("stages")) for r in rec], [("TM_Quest", stages)], rec)
                with open(log_file, encoding="utf-8") as f:
                    self.assertIn(logged, f.read())

    def test_safety_limit_skips_native_helpers(self):
        # In the shared Data folder, past the limit, a bare loose all-native helper the mod's one script calls isn't
        # one of the mod's unread scripts: no safety-limit note (0.2.0 counted it as "at least 1 more"). A helper
        # with code is one: the note says so.
        for name, flags, note in (("native", 0x3, False), ("with code", 0, True)):
            with self.subTest(name):
                data = self.p(name, "Data")
                tm_world(data)
                scr = os.path.join(data, "Scripts")
                write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "Quest",
                                                                    ("Helper", "DoThing", [])))
                write(os.path.join(scr, "Helper.pex"), mk.pex("Helper", "ScriptObject",
                                                              functions=[("DoThing", [], [], [], flags)]))
                mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
                old, scripts.MAX_SCRIPTS = scripts.MAX_SCRIPTS, 1
                try:
                    mods, notes, summary = drift.init(mod, [data], TOOLS)
                finally:
                    scripts.MAX_SCRIPTS = old
                limit = [n for n in notes if "safety limit" in n]
                self.assertEqual(limit, ["stopped after 1 of your mod's own scripts; at least 1 more weren't read "
                                         "(a safety limit)"] if note else [], notes)
                self.assertFalse([n for n in notes if "Helper" in n], notes)
                self.assertEqual(summary["scripts"], 1)

    def test_safety_limit_is_a_note(self):
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2([
            ("scripts/SM/Main.pex", calls("SM:Main", "Quest", ("TM:Base", "Hello", []))),
            ("scripts/SM/Other.pex", calls("SM:Other", "Quest")), ("scripts/SM/Third.pex", calls("SM:Third", "Quest"))]))
        mod = self.mod_plugin(os.path.join(src, "ScriptMod.esm"))
        old, scripts.MAX_SCRIPTS = scripts.MAX_SCRIPTS, 1
        try:
            mods, notes, summary = drift.init(mod, [data], TOOLS)
        finally:
            scripts.MAX_SCRIPTS = old
        self.assertIn("stopped after 1 of your mod's own scripts; at least 2 more weren't read (a safety limit)",
                      notes)
        self.assertEqual(summary["scripts"], 1)

    def test_safety_limit_native_helper_is_logged_as_left_out(self):
        # Past the limit, a bare loose all-native helper the mod's code reaches is left out, and the log says so.
        # (A code-only script that isn't the mod's never reaches that check, so it needs no log line.)
        data = self.p("Data")
        tm_world(data)
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "Quest", ("Helper", "DoThing", [])))
        write(os.path.join(scr, "Helper.pex"), mk.pex("Helper", "ScriptObject",
                                                      functions=[("DoThing", [], [], [], 0x3)]))
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
        log_file = self.p("limit.log")
        old, scripts.MAX_SCRIPTS = scripts.MAX_SCRIPTS, 1
        try:
            code, out = run("drift", "init", mod, "-o", self.p("m.json"), "--data", data,
                            "--pex-tools", TOOLS.folder, "--log", log_file)
        finally:
            scripts.MAX_SCRIPTS = old
        self.assertEqual(code, 0, out)
        with open(log_file, encoding="utf-8") as f:
            self.assertIn("every function is native (a DLL's script): left out past the safety limit, not counted as "
                          "ScriptMod.esm's", f.read())

    def test_safety_limit_counts_only_the_mods_scripts(self):
        # The plugin is in the shared Data folder. ZZ:Quest is a loose-installed master's script that the mod's quest
        # names too: it isn't the mod's, so it isn't counted (0.2.0 counted every loose script left in the queue).
        data = self.p("Data")
        tm_world(data)
        write(os.path.join(data, "ZZMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
            mk.record("QUST", 0x01000800, [mk.edid("ZZ_Quest"), mk.vmad([("ZZ:Quest", [])])])])]))
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "ZZ", "Quest.pex"), mk.pex("ZZ:Quest", "Quest"))
        write(os.path.join(scr, "SM", "Main.pex"), calls("SM:Main", "Quest", ("SM:Other", "Go", [])))
        write(os.path.join(scr, "SM", "Other.pex"), calls("SM:Other", "ScriptObject"))
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"),
                              masters=("Starfield.esm", "TestMaster.esm", "ZZMaster.esm"),
                              vmad=mk.vmad([("SM:Main", []), ("ZZ:Quest", [])]))
        old, scripts.MAX_SCRIPTS = scripts.MAX_SCRIPTS, 1
        try:
            mods, notes, summary = drift.init(mod, [data], TOOLS)
        finally:
            scripts.MAX_SCRIPTS = old
        self.assertIn("stopped after 1 of your mod's own scripts; at least 1 more weren't read (a safety limit)",
                      notes)
        self.assertEqual(summary["scripts"], 1)

    def test_safety_limit_unread_fragment_stays_the_mods(self):
        # The mod's own fragment script on the master quest it overrides isn't read past the limit (AA:First is
        # read first), but it's still the mod's: its stage on the master quest is credited (0.2.0 dropped it as
        # the master's fragment script).
        qf = "Fragments:Quests:QF_TM_Quest_01000800"
        frag = mk.pex(qf, "Quest", functions=[("Fragment_Stage_0010", [], [("::t1", "Bool")], [
            ("callmethod", ["ident:SetStage", "ident:self", "ident:::t1", "int:20"])])])
        tail = mk.quest_tail(qf, fragments=[(10, qf, "Fragment_Stage_0010")])
        for limit, label in ((1, "past the limit"), (scripts.MAX_SCRIPTS, "no limit reached")):
            with self.subTest(label):
                data, src = self.p(label, "Data"), self.p(label, "src")
                tm_world(data)
                write(os.path.join(src, "ScriptMod - Main.ba2"), mk.ba2([
                    ("scripts/AA/First.pex", calls("AA:First", "Quest")),
                    ("scripts/Fragments/Quests/QF_TM_Quest_01000800.pex", frag)]))
                mod = os.path.join(src, "ScriptMod.esm")
                write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [mk.group("QUST", [
                    mk.record("QUST", 0x01000800, [mk.edid("TM_Quest"), mk.vmad([], tail=tail)]),
                    mk.record("QUST", 0x02000800, [mk.edid("SM_Quest"), mk.vmad([("AA:First", [])])])])]))
                old, scripts.MAX_SCRIPTS = scripts.MAX_SCRIPTS, limit
                try:
                    mods, notes, summary = drift.init(mod, [data], TOOLS)
                finally:
                    scripts.MAX_SCRIPTS = old
                rec = mods["masters"]["TestMaster.esm"]["records"]
                self.assertEqual([(r["edid"], r.get("stages")) for r in rec], [("TM_Quest", [20])], rec)
                self.assertEqual(summary["scripts"], 1 if limit == 1 else 2)
                self.assertEqual(any("safety limit" in n for n in notes), limit == 1, notes)

    def test_loose_fragment_and_alias_scripts(self):
        # A loose install of a mod whose quest has a fragment script and an alias script: both are found through
        # the VMAD's fragment section, next to the plugin and in the shared Data folder alike. A constant stage
        # above 65535 isn't a stage number: the quest is marked "not known".
        qf = "Fragments:Quests:QF_SM_Quest_02000800"
        frag = mk.pex(qf, "Quest", variables=[("::TargetQuest_var", "Quest")],
                      properties=[("TargetQuest", "Quest", "::TargetQuest_var")],
                      functions=[("Fragment_Stage_0010", [], [("::t1", "Bool")], [
                          ("callmethod", ["ident:SetStage", "ident:::TargetQuest_var", "ident:::t1", "int:20"]),
                          ("callmethod", ["ident:SetStage", "ident:::TargetQuest_var", "ident:::t1", "int:70000"])])])
        alias = calls("SM:AliasScript", "ReferenceAlias", ("TM:Base", "Hello", []))
        tail = mk.quest_tail(qf, [("TargetQuest", 1, 0x01000800)], fragments=[(10, qf, "Fragment_Stage_0010")],
                             aliases=[(0, [("SM:AliasScript", [])])])
        for where in ("own folder", "Data folder"):
            with self.subTest(where):
                data = self.p(where, "Data")
                folder = data if where == "Data folder" else self.p(where, "src")
                tm_world(data)
                write(os.path.join(folder, "Scripts", "Fragments", "Quests", "QF_SM_Quest_02000800.pex"), frag)
                write(os.path.join(folder, "Scripts", "SM", "AliasScript.pex"), alias)
                # Another mod's loose scripts in the shared folder aren't read.
                write(os.path.join(data, "Scripts", "Fragments", "Quests", "QF_Other_00000800.pex"), b"not read")
                write(os.path.join(data, "Scripts", "Other", "Unrelated.pex"), b"not read")
                mod = self.mod_plugin(os.path.join(folder, "ScriptMod.esm"), vmad=mk.vmad([], tail=tail))
                mods, notes, summary = drift.init(mod, [data], TOOLS)
                tm = mods["masters"]["TestMaster.esm"]
                self.assertEqual(tm["functions"], {"scripts/TM/Base.pex": ["Hello"]})
                rec = tm["records"]
                self.assertEqual([(r["edid"], r["stages"]) for r in rec], [("TM_Quest", [20])])
                self.assertIn(f"Stages set by script {qf}", rec[0]["why"])
                self.assertIn("isn't listed", rec[0]["why"])
                self.assertEqual(summary["scripts"], 2)
                self.assertFalse([n for n in notes if "couldn't read" in n], notes)

    def test_shared_data_folder_namespaces(self):
        # The plugin is in the Data folder: Data\Scripts holds every mod's loose scripts. The mod's own are the ones
        # in its namespace (SM). FW:Api belongs to FrameworkMaster.esm (installed loose; its quest names FW:Quest),
        # so its call to TM:Api.Pong isn't the mod's. A loose copy of a master script is a note.
        data = self.p("Data")
        tm_world(data)
        write(os.path.join(data, "FrameworkMaster.esm"), mk.plugin(0x1, ["Starfield.esm"], [mk.group("QUST", [
            mk.record("QUST", 0x01000800, [mk.edid("FW_Quest"), mk.vmad([("FW:Quest", [])])])])]))
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "FW", "Quest.pex"), mk.pex("FW:Quest", "Quest"))
        write(os.path.join(scr, "FW", "Api.pex"), calls("FW:Api", "ScriptObject", ("TM:Api", "Pong", [])))
        write(os.path.join(scr, "SM", "Main.pex"), calls("SM:Main", "Quest", ("FW:Api", "DoIt", []),
                                                         ("SM:Helper", "Go", [])))
        write(os.path.join(scr, "SM", "Helper.pex"), calls("SM:Helper", "ScriptObject", ("TM:Base", "Hello", [])))
        write(os.path.join(scr, "TM", "Base.pex"), tm_base())
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"),
                              masters=("Starfield.esm", "TestMaster.esm", "FrameworkMaster.esm"))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]})
        self.assertEqual(summary["scripts"], 2)
        self.assertTrue(any("holds loose copies of 1 master script(s) your scripts call (scripts/TM/Base.pex)" in n
                            for n in notes), notes)

    def test_shared_data_folder_bare_helper_reached_by_code(self):
        # The plugin is in the Data folder and names only ScriptModMain (no namespace). Its helper ScriptModHelper,
        # reached only through a callstatic, and its parent ScriptModBase are the mod's too (0.1.x read them), so
        # the helper's call to TM:Base.Hello is found. Another mod's bare loose script nothing of ours references
        # isn't read, and a loose bare copy of a master archive script the helper reaches stays the master's.
        data = self.p("Data")
        tm_world(data)
        write(os.path.join(data, "TestMaster - Extra.ba2"), mk.ba2([("scripts/MasterBare.pex", mk.pex("MasterBare",
                                                                                                  "ScriptObject"))]))
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "ScriptModBase",
                                                            ("ScriptModHelper", "Go", [])))
        write(os.path.join(scr, "ScriptModBase.pex"), calls("ScriptModBase", "Quest", ("TM:Api", "Pong", [])))
        write(os.path.join(scr, "ScriptModHelper.pex"), calls("ScriptModHelper", "ScriptObject",
                                                              ("TM:Base", "Hello", []),
                                                              variables=[("Other", "MasterBare")]))
        write(os.path.join(scr, "MasterBare.pex"), b"someone's loose copy: not read")
        write(os.path.join(scr, "OtherModScript.pex"), b"another mod's script: not read")
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"],
                         {"scripts/TM/Api.pex": ["Pong"], "scripts/TM/Base.pex": ["Hello"]}, notes)
        self.assertEqual(summary["scripts"], 3)
        self.assertFalse([n for n in notes if "couldn't read" in n], notes)

    def test_shared_data_folder_bare_type_is_not_enough(self):
        # A bare loose script the mod's script only declares a variable of (another mod's object it holds) isn't
        # the mod's: its call to TM:Api.Pong isn't listed. The bare helpers it calls with callstatic are, and a note
        # lists them (20 names, then "and N more").
        data = self.p("Data")
        tm_world(data)
        scr = os.path.join(data, "Scripts")
        helpers = [f"ScriptModHelper{i:02d}" for i in range(22)]
        write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "Quest", ("TM:Base", "Hello", []),
                                                            *[(h, "Go", []) for h in helpers],
                                                            variables=[("Held", "OtherModThing")]))
        for h in helpers:
            write(os.path.join(scr, h + ".pex"), calls(h, "ScriptObject"))
        write(os.path.join(scr, "OtherModThing.pex"), calls("OtherModThing", "ScriptObject", ("TM:Api", "Pong", [])))
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]}, notes)
        self.assertEqual(summary["scripts"], 23)
        self.assertIn(f"22 loose script(s) in {scr} with no namespace (or Fragments:) were read as your mod's own "
                      f"because your scripts extend them or call them with callstatic: {', '.join(helpers[:20])} "
                      f"and 2 more", notes)

    def test_shared_data_folder_all_native_script_is_left_out(self):
        # A bare loose script the mod calls with callstatic whose functions are all native (an SFSE plugin's script)
        # isn't read as the mod's and isn't in the note. One with a native and a normal function still is.
        data = self.p("Data")
        tm_world(data)
        scr = os.path.join(data, "Scripts")
        write(os.path.join(scr, "ScriptModMain.pex"), calls("ScriptModMain", "Quest", ("TM:Base", "Hello", []),
                                                            ("DllApi", "DoThing", []), ("MixedHelper", "Go", [])))
        write(os.path.join(scr, "DllApi.pex"), mk.pex("DllApi", "ScriptObject", functions=[
            ("DoThing", [], [], [], 0x3), ("Other", [("a", "Int")], [], [], 0x3)]))
        write(os.path.join(scr, "MixedHelper.pex"), mk.pex("MixedHelper", "ScriptObject", functions=[
            ("Native", [], [], [], 0x2), ("Go", [], [], [])]))
        mod = self.mod_plugin(os.path.join(data, "ScriptMod.esm"), vmad=mk.vmad([("ScriptModMain", [])]))
        mods, notes, summary = drift.init(mod, [data], TOOLS)
        self.assertEqual(mods["masters"]["TestMaster.esm"]["functions"], {"scripts/TM/Base.pex": ["Hello"]}, notes)
        self.assertEqual(summary["scripts"], 2)
        self.assertIn(f"1 loose script(s) in {scr} with no namespace (or Fragments:) were read as your mod's own "
                      f"because your scripts extend them or call them with callstatic: MixedHelper", notes)
        lines = [x for x in notes if "DllApi" in x]
        self.assertEqual(lines, [])

    def test_failed_script_part_says_so(self):
        data, src = self.p("Data"), self.p("src")
        tm_world(data)
        mod = os.path.join(src, "ScriptMod.esm")
        write(mod, mk.plugin(0x1, ["Starfield.esm", "TestMaster.esm"], [
            mk.group("QUST", [mk.record("QUST", 0x01000800, [mk.edid("TM_Quest")])])]))

        def broken(*_a):
            raise scripts.ScriptError("made-up failure")
        old, scripts.analyze = scripts.analyze, broken
        try:
            code, out = run("drift", "init", mod, "-o", self.p("m.json"), "--data", data, "--pex-tools", TOOLS.folder)
        finally:
            scripts.analyze = old
        self.assertEqual(code, 0, out)
        self.assertIn(": 1 overridden record(s) in 1 master(s)\n", out)
        self.assertNotIn("read None", out)
        self.assertNotIn("function(s) your scripts call", out)
        self.assertIn("note: scripts not read: made-up failure", out)
        self.assertIn("Next: add the quest stages your scripts set and the master script functions they call by "
                      "hand", out)
        with open(self.p("m.json"), encoding="utf-8") as f:
            self.assertIn("its scripts couldn't be read", json.load(f)["about"])


# ---- creations: the Creations change report -------------------------------------------------------------------
ID_A, ID_B, ID_C, ID_D = ("TM_00000000-0000-0000-0000-00000000000" + c for c in "abcd")


class TestCreations(Temp):
    def setUp(self):
        super().setUp()
        self.cat, self.saved = self.p("game", "ContentCatalog.txt"), self.p("mine", "ContentCatalog-saved.txt")

    def base(self):
        return {ID_A: mk.creation("Example Ships", files=["ExampleShips.esm", "ExampleShips - Main.ba2"]),
                ID_B: mk.creation("Old Example Patch", version="1757190740.0.9.0"),
                ID_C: mk.creation("Example Hats")}

    def go(self, *extra):
        return run("creations", "--catalog", self.cat, "--saved", self.saved, *extra)

    def first(self, entries=None):
        write(self.cat, mk.catalog(self.base() if entries is None else entries))
        code, out = self.go()
        self.assertEqual(code, 0, out)
        return out

    def test_first_run_saves_a_byte_copy(self):
        out = self.first()
        self.assertIn("(3 Creations)", out)
        self.assertIn("RESULT: SAVED a first copy", out)
        with open(self.cat, "rb") as a, open(self.saved, "rb") as b:
            self.assertEqual(a.read(), b.read())
        code, out = self.go("--json")
        self.assertEqual(code, 0, out)
        rep = json.loads(out)
        self.assertEqual((rep["result"], rep["exit"], rep["counts"]["unchanged"]), ("no changes", 0, 3))

    def test_first_run_json(self):
        write(self.cat, mk.catalog(self.base()))
        code, out = self.go("--json")
        rep = json.loads(out)
        self.assertEqual((code, rep["result"], rep["first_copy_saved"], rep["counts"]["current"]),
                         (0, "first copy saved", True, 3))

    def test_no_change_and_timestamp_only(self):
        self.first()
        code, out = self.go()
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: NO CHANGES since the saved copy", out)
        e = self.base()
        e[ID_A]["Timestamp"] += 500
        e[ID_C]["Timestamp"] += 9
        write(self.cat, mk.catalog(e))
        code, out = self.go()
        self.assertEqual(code, 0, out)
        self.assertIn("Unchanged: 1. Timestamp-only changes (the game rewrites these when you load a save): 2", out)
        self.assertNotIn("UPDATED", out)

    def test_added_removed_updated(self):
        self.first()
        e = self.base()
        del e[ID_B]
        e[ID_D] = mk.creation("Example Outfits", version="1757190999.1.2.0",
                              files=["ExampleOutfits.esm", "ExampleOutfits - Main.ba2"])
        e[ID_A].update(Version="1757191000.1.1.0", FilesSize=1048576, AchievementSafe=False,
                       Files=["exampleships.ESM", "ExampleShips - Main.ba2",
                              "ExampleShips - Textures.ba2"], Timestamp=1)
        e[ID_C]["Title"] = "Example Hats Remastered"
        write(self.cat, mk.catalog(e))
        code, out = self.go()
        self.assertEqual(code, 1, out)
        self.assertIn(f"ADDED   Example Outfits ({ID_D}) version 1.2.0, files: ExampleOutfits.esm, "
                      f"ExampleOutfits - Main.ba2", out)
        self.assertIn(f"REMOVED Old Example Patch ({ID_B}) version 0.9.0, files: OldExamplePatch.esm", out)
        # The case of a file name doesn't count as a change (Windows file names ignore case).
        self.assertIn(f"UPDATED Example Ships ({ID_A}): version 1.0.0 -> 1.1.0; files added: ExampleShips - "
                      f"Textures.ba2; size 0 -> 1048576; achievement-friendly yes -> no", out)
        self.assertIn(f"UPDATED Example Hats Remastered ({ID_C}): renamed from \"Example Hats\"", out)
        self.assertIn("RESULT: CHANGES: 1 added, 1 removed, 2 updated.", out)
        self.assertIn("--save", out)
        code, out = self.go("--json")
        rep = json.loads(out)
        self.assertEqual((code, rep["exit"], rep["result"]), (1, 1, "changes"))
        self.assertEqual(rep["counts"], {"current": 3, "saved": 3, "added": 1, "removed": 1, "updated": 2,
                                         "unchanged": 0, "timestamp_only": 0})
        self.assertEqual(rep["added"][0]["version"], "1757190999.1.2.0")  # JSON keeps the raw version
        ships = next(u for u in rep["updated"] if u["id"] == ID_A)["changes"]
        self.assertEqual(ships["version"], {"old": "1757190740.1.0.0", "new": "1757191000.1.1.0"})
        self.assertEqual(ships["files"], {"added": ["ExampleShips - Textures.ba2"], "removed": []})
        self.assertEqual(ships["files_size"], {"old": 0, "new": 1048576})
        self.assertEqual(ships["achievement_safe"], {"old": True, "new": False})
        self.assertEqual([u["title"] for u in rep["updated"]], ["Example Hats Remastered", "Example Ships"])

    def test_files_removed_and_unknown_field(self):
        self.first()
        e = self.base()
        e[ID_A]["Files"] = ["ExampleShips.esm"]
        e[ID_C]["NewField"] = 7
        write(self.cat, mk.catalog(e))
        code, out = self.go()
        self.assertEqual(code, 1, out)
        self.assertIn("files removed: ExampleShips - Main.ba2", out)
        self.assertIn(f"UPDATED Example Hats ({ID_C}): NewField null -> 7", out)

    def test_save_replaces_and_plain_run_leaves_it(self):
        self.first()
        e = self.base()
        del e[ID_C]
        write(self.cat, mk.catalog(e))
        with open(self.saved, "rb") as f:
            before = f.read()
        for _ in range(2):  # without --save the report repeats and the saved copy stays as it was
            code, out = self.go()
            self.assertEqual(code, 1, out)
            with open(self.saved, "rb") as f:
                self.assertEqual(f.read(), before)
        code, out = self.go("--save")
        self.assertEqual(code, 1, out)
        self.assertIn("the saved copy is now the current catalog", out)
        with open(self.cat, "rb") as a, open(self.saved, "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertEqual([n for n in os.listdir(self.p("mine")) if n.endswith(".tmp")], [])
        code, out = self.go()
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: NO CHANGES", out)

    def test_bad_input(self):
        code, out = self.go()
        self.assertEqual(code, 3, out)
        self.assertIn("the Creations catalog wasn't found", out)
        self.assertIn("Fix: start the game once", out)
        self.assertFalse(os.path.exists(self.saved))
        for data, says in ((b"{not json", "isn't valid JSON"), (b"[1, 2]", "not a JSON object"),
                           (b'{"TM_x": {"Title": "A"}}', "no \"ContentCatalog\" header"),
                           (b'{"ContentCatalog": {}, "TM_x": 5}', "isn't an object"), (b"\xff\xfe{", "UTF-8"),
                           # nested too deeply for Python's JSON reader: a plain refusal, not "unexpected error"
                           (b'{"ContentCatalog": {}, "TM_x": ' + b"[" * 100000 + b"]" * 100000 + b"}",
                            "nested too deeply")):
            write(self.cat, data)
            code, out = self.go()
            self.assertEqual(code, 3, out)
            self.assertIn(says, out)
            self.assertIn("Fix:", out)
            self.assertFalse(os.path.exists(self.saved))
        self.first()
        write(self.saved, b"broken")
        code, out = self.go()
        self.assertEqual(code, 3, out)
        self.assertIn("the saved copy", out)
        self.assertIn("Fix: delete it, or give --saved another file", out)

    def test_too_big(self):
        old = creations.MAX_BYTES
        creations.MAX_BYTES = 10
        try:
            write(self.cat, mk.catalog(self.base()))
            code, out = self.go()
        finally:
            creations.MAX_BYTES = old
        self.assertEqual(code, 3, out)
        self.assertIn("over the 64 MB", out)

    def test_saved_in_game_catalog_folder_refused(self):
        write(self.cat, mk.catalog(self.base()))
        for saved in (self.p("game", "copy.txt"), self.cat):
            code, out = run("creations", "--catalog", self.cat, "--saved", saved)
            self.assertEqual(code, 3, out)
            self.assertIn("in the folder that holds the game's catalog", out)
        self.assertEqual(sorted(os.listdir(self.p("game"))), ["ContentCatalog.txt"])

    def test_default_saved_under_catalog_folder_allowed(self):
        # a catalog copied to a folder above the default state folder (such as the home folder) still runs
        from unittest import mock
        write(self.p("ContentCatalog.txt"), mk.catalog(self.base()))
        env = {"LOCALAPPDATA": self.p("local"), "XDG_STATE_HOME": self.p("local")}
        with mock.patch.dict(os.environ, env):
            code, out = run("creations", "--catalog", self.p("ContentCatalog.txt"))
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.isfile(self.p("local", "sf-patch-day", "ContentCatalog-saved.txt")))

    def test_odd_numbers_refused(self):
        # a 5000-digit number and NaN are refused as not a catalog, not an unexpected error or bad JSON output
        for data in (b'{"ContentCatalog": {}, "TM_x": {"FilesSize": 1' + b"0" * 5000 + b"}}",
                     b'{"ContentCatalog": {}, "TM_x": {"FilesSize": NaN}}'):
            write(self.cat, data)
            code, out = self.go()
            self.assertEqual(code, 3, out)
            self.assertIn("isn't a Creations catalog", out)
            self.assertNotIn("unexpected error", out)
            self.assertFalse(os.path.exists(self.saved))

    def test_overflowing_float_refused(self):
        # 1e999 reads as inf; it is refused as not a catalog, so --json never writes a bare Infinity
        write(self.cat, b'{"ContentCatalog": {}, "TM_x": {"FilesSize": 1e999}}')
        code, out = self.go("--json")
        self.assertEqual(code, 3, out)
        self.assertIn("isn't a Creations catalog (a number too large to read)", out)
        self.assertNotIn("Infinity", out)

    def test_control_characters_in_titles_escaped(self):
        # a title can't add a fake RESULT line or send terminal codes
        e = self.base()
        self.first(e)
        e[ID_B] = dict(e[ID_B], Title="X\nRESULT: NO CHANGES since the saved copy.\x1b[2J")
        e["TM_new"] = mk.creation("New\rHat\x9b")
        write(self.cat, mk.catalog(e))
        code, out = self.go()
        self.assertEqual(code, 1, out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\r", out)
        self.assertNotIn("\x9b", out)
        self.assertEqual([ln for ln in out.splitlines() if ln.startswith("RESULT:")][0][:16], "RESULT: CHANGES:")
        self.assertEqual(len([ln for ln in out.splitlines() if ln.startswith("RESULT:")]), 1)
        self.assertIn('renamed from "Old Example Patch"', out)
        self.assertIn("X\\x0aRESULT: NO CHANGES since the saved copy.\\x1b[2J", out)
        self.assertIn("New\\x0dHat\\x9b", out)

    def test_format_and_line_separator_characters_in_titles_escaped(self):
        # (0.5.2) A right-to-left override could reorder a line, and a line or paragraph separator could break it:
        # titles and file lists come from other authors, so they get the same escaping as the dlls report.
        e = self.base()
        self.first(e)
        e[ID_C] = dict(e[ID_C], Title="Hats\u202edlrow\u2028\u2029\u200bX")
        e["TM_new"] = mk.creation("New", files=["New\u202epse.esm"])
        write(self.cat, mk.catalog(e))
        code, out = self.go()
        self.assertEqual(code, 1, out)
        for ch in ("\u202e", "\u2028", "\u2029", "\u200b"):
            self.assertNotIn(ch, out)
        self.assertIn("UPDATED Hats\\u202edlrow\\u2028\\u2029\\u200bX", out)
        self.assertIn("files: New\\u202epse.esm", out)
        self.assertEqual(creations.clean("a\x1b\u202eb"), "a\\x1b\\u202eb")

    def test_folder_names_in_head_lines_escaped(self):
        # (0.5.2 code-review round 1) The catalog and saved-copy paths in the head lines are escaped too.
        self.cat = self.p("ga\u202eme", "ContentCatalog.txt")
        self.saved = self.p("mi\u202ene", "ContentCatalog-saved.txt")
        out = self.first()
        self.assertIn("ga\\u202eme", out)
        self.assertIn("mi\\u202ene", out)  # the RESULT: SAVED line
        self.assertNotIn("\u202e", out)
        code, out = self.go()
        self.assertEqual(code, 0, out)
        self.assertIn("Compared with: ", out)
        self.assertIn("mi\\u202ene", out)
        self.assertNotIn("\u202e", out)

    def test_reupload_same_version_shown(self):
        e = self.base()
        self.first(e)
        e[ID_B] = dict(e[ID_B], Version="1760000000.0.9.0")
        write(self.cat, mk.catalog(e))
        code, out = self.go()
        self.assertEqual(code, 1, out)
        self.assertIn("re-uploaded (same version 0.9.0)", out)

    def test_bom_and_missing_fields(self):
        write(self.cat, mk.catalog(self.base(), bom=True))
        self.assertEqual(self.go()[0], 0)
        e = self.base()
        e[ID_D] = {"Timestamp": 3}
        write(self.cat, mk.catalog(e, bom=True))
        code, out = self.go()
        self.assertEqual(code, 1, out)
        self.assertIn(f"ADDED   (no title) ({ID_D}) version (none), files: (none)", out)

    def test_show_version_and_defaults(self):
        self.assertEqual(creations.show_version("1757190740.1.0.0"), "1.0.0")
        self.assertEqual(creations.show_version("1.0.0"), "1.0.0")
        self.assertEqual(creations.show_version("123.4"), "123.4")
        self.assertEqual(creations.show_version(None), "")
        env = {"LOCALAPPDATA": self.p("local"), "XDG_STATE_HOME": self.p("state")}
        saved = paths.default_saved_catalog(env)
        self.assertTrue(saved.endswith(os.path.join("sf-patch-day", "ContentCatalog-saved.txt")), saved)
        cats = paths.candidate_catalogs(env)
        self.assertTrue(cats and all(c.endswith(os.path.join("Starfield", "ContentCatalog.txt")) for c in cats))
        if sys.platform == "win32":
            self.assertEqual(cats, [os.path.join(self.p("local"), "Starfield", "ContentCatalog.txt")])
            self.assertTrue(saved.startswith(self.p("local")))
        else:
            self.assertTrue(saved.startswith(self.p("state")))
            self.assertTrue(all("compatdata" in c for c in cats))

    def test_default_catalog_missing_names_the_place(self):
        old = paths.candidate_catalogs
        paths.candidate_catalogs = lambda env=None: [self.p("nowhere", "ContentCatalog.txt")]
        try:
            code, out = run("creations", "--saved", self.saved)
        finally:
            paths.candidate_catalogs = old
        self.assertEqual(code, 3, out)
        self.assertIn(self.p("nowhere", "ContentCatalog.txt"), out)

    def test_verbose_logs_timestamp_only_ids(self):
        self.first()
        e = self.base()
        e[ID_C]["Timestamp"] = 1
        write(self.cat, mk.catalog(e))
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = cli.main(["creations", "--catalog", self.cat, "--saved", self.saved, "--verbose"])
        self.assertEqual(code, 0)
        self.assertIn(f"Timestamp-only changes (not reported): ['{ID_C}']", err.getvalue())
        self.assertIn("[end] exit code 0", err.getvalue())

    def test_help(self):
        code, out = run("creations", "--help")
        self.assertEqual(code, 0)
        self.assertIn("--save", out)
        self.assertIn("Timestamp", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
