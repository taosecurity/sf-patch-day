# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""sf-patch-day tests. Run: python -I tests/test_sf_patch_day.py

Every DLL and plugin here is made up by tests/makers.py. The function checks use sf-pex-tools' own made-up test
archive; they need sf-pex-tools (SF_PEX_TOOLS, or a sf-pex-tools folder next to this repo) and skip without it.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import makers as mk  # noqa: E402
from sf_patch_day import cli, dlls, drift, pe, pextools  # noqa: E402
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
        self.assertEqual(run("dlls", "--game", self.p("nowhere"))[0], 3)
        self.assertEqual(run("dlls", self.p("x.zip"), "--game-version", "soon")[0], 3)
        self.assertEqual(run("dlls", self.p("missing.dll"), "--game-version", "1.16.300")[0], 3)
        self.assertEqual(run("dlls", "--no-such-option")[0], 3)


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
        self.assertIn("doesn't follow the mods file format", out)
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
        self.snap()

    def test_fingerprint(self):
        code, out = run("fingerprint", "TestMaster.esm", "--data", self.data)
        self.assertEqual(code, 0, out)
        self.assertIn("probe FormID 000802", out)  # the GLOB is the highest own probe-type record
        with Plugin(self.p("Data", "LightMaster.esm"), [self.data]) as p:
            self.assertEqual(p.mask, 0xFFF)

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
        self.assertEqual(code, 0, out)
        with open(logf, encoding="utf-8") as f:
            self.assertNotIn("can't list", f.read())
        plugin_module.clear_cache()

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


if __name__ == "__main__":
    unittest.main(verbosity=1)
